"""Train, evaluate and export SENTIVRA's network models.

    backend/.venv/Scripts/python research/experiments/train_network_models.py

Data: synthetic flows from app.demo.network_flows (see that module's
docstring). The script can't produce claims about real traffic, and the
model card says so next to every number.

Leakage controls (brief §28):
  * TRAIN, CALIBRATION and TEST are independently generated "days" (seeds
    101 / 202 / 303). No flow, host pairing or episode is shared between them.
  * The scaler is fit on TRAIN benign flows only.
  * The unsupervised models (Isolation Forest, autoencoder, statistical
    baseline) see only TRAIN benign flows. Labels are used to filter
    training data, which assumes a clean baseline; real baselines are
    rarely perfectly clean, and the model card says that.
  * Every threshold and calibration parameter is chosen on CALIBRATION.
    TEST is scored once, at the end.
  * One attack category (beaconing) is withheld from the supervised
    classifier's TRAIN and CALIBRATION data, to measure how it handles an
    attack type it has never seen, next to the unsupervised layers.

Outputs:
  models/network/{isolation_forest,autoencoder,classifier}/ (artifact + metadata.json)
  research/evaluation/network/report.json
"""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

import lightgbm as lgb
import numpy as np
import onnxruntime as ort
from skl2onnx import to_onnx
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import RobustScaler

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import MODELS_DIR, environment, write_model, write_report

from app.demo.network_flows import CATEGORIES, ScenarioConfig, generate
from app.detectors.network import batch_rules
from app.detectors.network.features import FEATURE_NAMES, feature_matrix
from app.detectors.network.scoring import (
    ClassifierLayer,
    EmpiricalTail,
    OnnxAnomalyLayer,
    RobustScaling,
    StatisticalLayer,
    fuse,
)
from app.ml.metrics import (
    binary_metrics,
    bootstrap_ci,
    latency_ms,
    threshold_for_max_fpr,
)

VERSION = "0.1.0"
ALPHA = 0.01            # unsupervised layers fire at p <= 1% vs benign calibration traffic
CLASSIFIER_MAX_FPR = 0.01
HELD_OUT = "beaconing"
FUSION_MAX_FPR = 0.01   # the fused cut is the lowest one meeting this FPR on the calibration split
SPLIT_SEEDS = {"train": 101, "calibration": 202, "test": 303}

# Changes made after looking at a test result are recorded here, so the
# model card can say exactly how much of the design was test-informed.
REVISIONS = [
    {
        "run": 1,
        "change": "fusion cut fixed at 0.4 (any single model layer could flag a flow)",
        "observed_on_test": "fused flow-level FPR 0.0288 vs ~0.01 per layer: the union of layers' "
                            "false positives",
        "revision": "fusion cut is now selected on the CALIBRATION split as the lowest cut with "
                    f"FPR <= {FUSION_MAX_FPR}; no model, feature or threshold was re-tuned on test",
    },
    {
        "run": 2,
        "change": "batch verdicts counted any model-flagged flow as evidence",
        "observed_on": "benign-only uploads (not the test split): every 2,400-flow benign batch got a "
                       "MEDIUM alert, because ~0.7% of benign flows pass the cut by construction",
        "revision": "model evidence now raises a batch's severity only when the number of flagged flows "
                    "is significantly above what the calibration benign flag rate predicts (binomial "
                    "tail p < 0.001). The flow-level metrics in this report are unaffected",
    },
]
SCENARIO = {"hosts": 80, "hours": 8.0, "benign_flows_per_host_hour": 40}


def load_split(seed: int):
    flows = generate(ScenarioConfig(**SCENARIO, episodes={c: 2 for c in CATEGORIES}, seed=seed))
    x = feature_matrix(flows)
    labels = np.array([f.label for f in flows])
    return flows, x, labels, (labels != "benign").astype(int)


def per_category_recall(labels: np.ndarray, predicted: np.ndarray) -> dict[str, float]:
    out = {}
    for cat in CATEGORIES:
        mask = labels == cat
        if mask.any():
            out[cat] = round(float(predicted[mask].mean()), 4)
    out["benign_false_positive_rate"] = round(float(predicted[labels == "benign"].mean()), 4)
    return out


def main() -> None:
    splits = {name: load_split(seed) for name, seed in SPLIT_SEEDS.items()}
    _, tr_x, tr_labels, tr_y = splits["train"]
    ca_flows, ca_x, ca_labels, ca_y = splits["calibration"]
    te_flows, te_x, te_labels, te_y = splits["test"]
    benign_train = tr_x[tr_y == 0]
    print({k: (len(v[0]), int(v[3].sum())) for k, v in splits.items()}, "(flows, anomalous flows)")

    # ---- scaling (TRAIN benign only) -------------------------------------
    scaler = RobustScaler().fit(benign_train)
    scaling = RobustScaling(scaler.center_.copy(), scaler.scale_.copy())
    xs_train = scaling.transform(benign_train)

    # ---- unsupervised models on TRAIN benign ------------------------------
    iforest = IsolationForest(n_estimators=200, max_samples=256, random_state=0).fit(xs_train)
    autoencoder = MLPRegressor(hidden_layer_sizes=(16, 6, 16), activation="relu", max_iter=400,
                               early_stopping=True, random_state=0).fit(xs_train, xs_train)

    if_dir, ae_dir, clf_dir = (MODELS_DIR / "network" / n for n in ("isolation_forest", "autoencoder", "classifier"))
    for d in (if_dir, ae_dir, clf_dir):
        d.mkdir(parents=True, exist_ok=True)
    sample = xs_train[:1].astype(np.float32)
    (if_dir / "model.onnx").write_bytes(
        to_onnx(iforest, sample, target_opset={"": 17, "ai.onnx.ml": 3}).SerializeToString())
    (ae_dir / "model.onnx").write_bytes(to_onnx(autoencoder, sample, target_opset=17).SerializeToString())

    # Check the exported graphs agree with scikit-learn before trusting them.
    if_session = ort.InferenceSession(str(if_dir / "model.onnx"), providers=["CPUExecutionProvider"])
    ae_session = ort.InferenceSession(str(ae_dir / "model.onnx"), providers=["CPUExecutionProvider"])
    probe = scaling.transform(te_x[:2000])
    if_diff = np.abs(if_session.run(None, {if_session.get_inputs()[0].name: probe.astype(np.float32)})[1].ravel()
                     - iforest.decision_function(probe)).max()
    ae_out = ae_session.run(None, {ae_session.get_inputs()[0].name: probe.astype(np.float32)})[0]
    ae_diff = np.abs(np.asarray(ae_out).reshape(len(probe), -1) - autoencoder.predict(probe)).max()
    print(f"ONNX parity: isolation_forest max|diff|={if_diff:.2e}, autoencoder max|diff|={ae_diff:.2e}")
    assert if_diff < 1e-3 and ae_diff < 1e-3, "ONNX export disagrees with scikit-learn"

    # ---- calibrate unsupervised layers on CALIBRATION benign -----------------
    placeholder = EmpiricalTail(np.zeros(2), 1)
    stat_layer = StatisticalLayer(scaling, placeholder, ALPHA)
    if_layer = OnnxAnomalyLayer("isolation_forest", if_session, scaling, placeholder, ALPHA)
    ae_layer = OnnxAnomalyLayer("autoencoder", ae_session, scaling, placeholder, ALPHA)
    ca_benign = ca_x[ca_y == 0]
    for layer in (stat_layer, if_layer, ae_layer):
        layer.tail = EmpiricalTail.fit(layer.raw_scores(ca_benign))

    # ---- supervised classifier (beaconing withheld from TRAIN and CALIBRATION)
    tr_keep = tr_labels != HELD_OUT
    ca_keep = ca_labels != HELD_OUT
    params = {"objective": "binary", "learning_rate": 0.05, "num_leaves": 31, "min_data_in_leaf": 20,
              "feature_fraction": 0.9, "bagging_fraction": 0.9, "bagging_freq": 1, "seed": 0,
              "deterministic": True, "force_row_wise": True, "verbose": -1}
    booster = lgb.train(params, lgb.Dataset(tr_x[tr_keep], tr_y[tr_keep], feature_name=list(FEATURE_NAMES)),
                        num_boost_round=300)
    ca_raw = booster.predict(ca_x[ca_keep], raw_score=True)
    platt = LogisticRegression(C=1e4).fit(ca_raw.reshape(-1, 1), ca_y[ca_keep])
    platt_a, platt_b = float(platt.coef_[0, 0]), float(platt.intercept_[0])
    clf_layer = ClassifierLayer(booster, platt_a, platt_b, threshold=0.5)
    clf_layer.threshold = threshold_for_max_fpr(ca_y[ca_keep], clf_layer.probabilities(ca_x[ca_keep]),
                                                CLASSIFIER_MAX_FPR)
    booster.save_model(str(clf_dir / "model.lgb.txt"))

    layers = {"statistical": stat_layer, "isolation_forest": if_layer, "autoencoder": ae_layer,
              "classifier": clf_layer}

    def fused(x: np.ndarray) -> np.ndarray:
        per_flow = zip(*(layer.score(x) for layer in layers.values()), strict=True)
        return np.array([fuse(list(r)) for r in per_flow])

    # ---- fusion cut, chosen on CALIBRATION -------------------------------------
    ca_fused = fused(ca_x)
    candidates = sorted(set(np.round(ca_fused[ca_fused > 0], 6)))
    fusion_cut = next(
        (float(c) for c in candidates if ((ca_fused >= c) & (ca_y == 0)).sum() / max((ca_y == 0).sum(), 1)
         <= FUSION_MAX_FPR),
        1.0,
    )
    # The benign flag rate at that cut is what the detector needs to decide
    # whether a batch has more flagged flows than chance would produce.
    benign_flag_rate = float(((ca_fused >= fusion_cut) & (ca_y == 0)).sum() / max((ca_y == 0).sum(), 1))
    print(f"fusion cut chosen on calibration: {fusion_cut:.4f} (benign flag rate {benign_flag_rate:.4f})")

    # ---- TEST: scored once ---------------------------------------------------
    results = {name: layer.score(te_x) for name, layer in layers.items()}
    fused_scores = np.array([fuse(list(r)) for r in zip(*results.values(), strict=True)])

    findings = batch_rules.evaluate(te_flows)
    index = {id(f): i for i, f in enumerate(te_flows)}
    in_rule = np.zeros(len(te_flows), dtype=int)
    for finding in findings:
        for member in finding.members:
            in_rule[index[id(member)]] = 1

    evaluation: dict[str, dict] = {}
    for name, res in results.items():
        pred = np.array([int(r.fired) for r in res])
        scores = np.array([r.probability if r.probability is not None else 1 - r.p_value for r in res])
        evaluation[name] = {
            "flow_level": binary_metrics(te_y, pred, scores).to_dict(),
            "per_category_recall": per_category_recall(te_labels, pred),
        }
    fused_pred = (fused_scores >= fusion_cut).astype(int)
    evaluation["fused_models"] = {
        "flow_level": binary_metrics(te_y, fused_pred, fused_scores).to_dict(),
        "per_category_recall": per_category_recall(te_labels, fused_pred),
        "bootstrap_95ci": bootstrap_ci(te_y, fused_pred),
    }
    rules_or_models = np.maximum(fused_pred, in_rule)
    evaluation["fused_models_plus_behavior_rules"] = {
        "flow_level": binary_metrics(te_y, rules_or_models).to_dict(),
        "per_category_recall": per_category_recall(te_labels, rules_or_models),
    }
    rule_hits = defaultdict(int)
    for finding in findings:
        rule_hits[finding.rule] += 1
    benign_findings = [f.rule for f in findings if all(m.label == "benign" for m in f.members)]
    evaluation["behavior_rules_episode_level"] = {
        "findings_by_rule": dict(rule_hits),
        "findings_on_benign_only_traffic": benign_findings,
        "episodes_in_test_per_category": 2,
    }

    single = [te_x[i:i + 1] for i in range(0, 2000, 4)]
    evaluation["latency"] = {
        "single_flow_all_layers": latency_ms(lambda x: [layer.score(x) for layer in layers.values()], single),
    }

    report = {
        "version": VERSION,
        "data": {"generator": "app.demo.network_flows", "scenario": SCENARIO, "split_seeds": SPLIT_SEEDS,
                 "flows": {k: len(v[0]) for k, v in splits.items()},
                 "anomalous_flows": {k: int(v[3].sum()) for k, v in splits.items()}},
        "held_out_from_classifier": HELD_OUT,
        "alpha": ALPHA,
        "fusion": {"cut": fusion_cut, "selected_on": "calibration", "max_fpr": FUSION_MAX_FPR,
                   "benign_flag_rate": benign_flag_rate},
        "revisions": REVISIONS,
        "classifier": {"threshold": clf_layer.threshold, "platt": [platt_a, platt_b]},
        "onnx_parity_max_abs_diff": {"isolation_forest": float(if_diff), "autoencoder": float(ae_diff)},
        "evaluation": evaluation,
        "environment": environment(),
    }
    write_report("network", report)

    # ---- metadata --------------------------------------------------------------
    datasets = [{"name": "SENTIVRA synthetic network flows", "role": "train / calibration / test",
                 "license": "Apache-2.0 (generated by this repository)",
                 "source": "backend/app/demo/network_flows.py",
                 "notes": f"independent seeds {SPLIT_SEEDS}; scenario {SCENARIO}"}]
    splits_meta = {"train_benign_flows": len(benign_train), "calibration_flows": len(ca_flows),
                   "test_flows": len(te_flows)}
    common = {
        "version": VERSION,
        "datasets": datasets,
        "splits": splits_meta,
        "split_method": "independently generated days (seeds 101/202/303); no flow shared between splits",
        "feature_schema": list(FEATURE_NAMES),
        "training_dataset": "SENTIVRA synthetic flows (demo data, not real traffic)",
        "limitations": [
            ("Trained and evaluated on synthetic flows from this repo's own generator. The metrics show "
             "the pipeline works end to end; they are not evidence of performance on real traffic."),
            "The generator defines both normal and anomalous behavior, so separability is optimistic.",
            ("The classifier's recall on the held-out category (beaconing) is a generator artifact: in this "
             "synthetic data, beacons share small response sizes with categories the classifier did see. "
             "Real beacons resemble ordinary small HTTPS requests."),
            "Per-flow features carry no DNS query-name features; DNS tunneling is caught by the behavior rule.",
            "Unsupervised training assumes a clean benign baseline.",
            ("The flow parser already reads CICFlowMeter/CIC-IDS2017 CSVs, but this script can't yet train "
             "from them (planned: Monday traffic as the benign baseline)."),
        ],
    }
    fused_test = evaluation["fused_models"]["flow_level"]

    def headline(name: str) -> dict[str, float]:
        m = evaluation[name]["flow_level"]
        return {k: m[k] for k in ("precision", "recall", "f1", "false_positive_rate", "pr_auc", "roc_auc")
                if m.get(k) is not None}

    write_model("network", "isolation_forest", if_dir / "model.onnx", {
        **common, "artifact_format": "onnx",
        "preprocessing": {"scaling": scaling.to_dict(), "tail": if_layer.tail.to_dict(), "alpha": ALPHA,
                          "statistical_baseline": {"tail": stat_layer.tail.to_dict(), "alpha": ALPHA},
                          "fusion": {"cut": fusion_cut, "selected_on": "calibration split",
                                     "max_fpr": FUSION_MAX_FPR, "benign_flag_rate": benign_flag_rate},
                          "input": "robust-scaled FEATURE_NAMES, float32"},
        "threshold": ALPHA, "threshold_policy": "fires when p-value vs benign calibration flows <= alpha",
        "evaluation_metrics": headline("isolation_forest"),
        "evaluation": {"test": evaluation["isolation_forest"], "fused_detector_test": fused_test,
                       "report": "research/evaluation/network/report.json"},
        "notes": "Also carries the statistical baseline (robust z-score tail) and the detector's fusion cut, "
                 "since all network layers share this scaling and calibration split.",
    })
    write_model("network", "autoencoder", ae_dir / "model.onnx", {
        **common, "artifact_format": "onnx",
        "preprocessing": {"scaling": scaling.to_dict(), "tail": ae_layer.tail.to_dict(), "alpha": ALPHA,
                          "architecture": "MLP 21-16-6-16-21 (ReLU), trained to reconstruct benign flows",
                          "input": "robust-scaled FEATURE_NAMES, float32"},
        "threshold": ALPHA, "threshold_policy": "fires when p-value of reconstruction error <= alpha",
        "evaluation_metrics": headline("autoencoder"),
        "evaluation": {"test": evaluation["autoencoder"], "report": "research/evaluation/network/report.json"},
    })
    write_model("network", "classifier", clf_dir / "model.lgb.txt", {
        **common, "artifact_format": "lightgbm_text",
        "preprocessing": {"input": "unscaled FEATURE_NAMES", "held_out_category": HELD_OUT},
        "threshold": clf_layer.threshold,
        "threshold_policy": f"lowest threshold with FPR <= {CLASSIFIER_MAX_FPR} on the calibration split",
        "calibration": {"method": "platt", "a": platt_a, "b": platt_b, "fit_on": "calibration split"},
        "evaluation_metrics": headline("classifier"),
        "evaluation": {"test": evaluation["classifier"], "report": "research/evaluation/network/report.json"},
    })

    print("\nTEST (synthetic), flow level")
    for name in (*layers, "fused_models", "fused_models_plus_behavior_rules"):
        m = evaluation[name]["flow_level"]
        print(f"  {name:34} P={m['precision']:.3f} R={m['recall']:.3f} F1={m['f1']:.3f} FPR={m['false_positive_rate']:.4f}")
    print("\nper-category recall")
    for name in (*layers, "fused_models_plus_behavior_rules"):
        print(f"  {name:34}", evaluation[name]["per_category_recall"])
    print("\nbehavior rules:", evaluation["behavior_rules_episode_level"])
    print("latency:", evaluation["latency"])


if __name__ == "__main__":
    main()
