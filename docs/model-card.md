# SENTIVRA Model Card

Every number in this document comes from `research/evaluation/<domain>/report.json`, produced by the training script named next to it. A metric is only reported with its dataset, split, model version and evaluation date (brief §33). If a model isn't trained, it says so; it doesn't get a placeholder score.

**Accuracy is deliberately never reported.** On imbalanced security data, a model that flags nothing can score very high accuracy.

## Status of every model

| Model | Directory | Status | Trained on |
|---|---|---|---|
| Network: Isolation Forest (+ statistical baseline) | `models/network/isolation_forest/` | Trained, v0.1.0 | Synthetic flows (demo data) |
| Network: autoencoder | `models/network/autoencoder/` | Trained, v0.1.0 | Synthetic flows (demo data) |
| Network: supervised classifier | `models/network/classifier/` | Trained, v0.1.0 | Synthetic flows (demo data) |
| Endpoint fleet baseline (for host rules; not an ML model) | `models/endpoint/fleet_baseline/` | Learned, v0.1.0 | Simulated endpoint fleet (benign only) |
| Endpoint behavioral Isolation Forest | — | **Not implemented** in this version | — |
| Phishing URL model | `models/phishing/url_model/` | **Not trained** | Dataset downloaded (PhiUSIIL, CC BY 4.0); see its dataset notes below |
| Prompt injection classifier | `models/prompt/prompt_injection/` | **Not trained** | Dataset downloaded (deepset/prompt-injections, Apache-2.0) |
| SQL injection classifier | `models/sql_injection/classifier/` | **Not trained** | SecLists SQLi lists downloaded (MIT) as positives; no benign corpus chosen yet |
| Malware static model (EMBER-style) | `models/malware/ember/` | **Not trained** | No dataset pulled. The EMBER reference repo named in the brief doesn't exist (see repository-analysis.md) |

`GET /api/v1/models` reports the same status, read live from each directory's `metadata.json`.

---

## Network anomaly models (v0.1.0)

**Read this first.** These models were trained and tested on **synthetic flows** from Sentivra's own generator (`backend/app/demo/network_flows.py`). The numbers below show the pipeline works end to end: leakage controls, calibration, ONNX export and fusion all behave as intended. They are **not evidence of performance on real network traffic**. The generator defines both normal and anomalous behavior, so the classes are far easier to separate than real traffic would be.

- **Training script:** `research/experiments/train_network_models.py`
- **Report:** `research/evaluation/network/report.json`
- **Evaluation date:** 2026-09-24
- **Environment:** Python 3.14.2, scikit-learn 1.9.1, LightGBM 4.7.0, numpy 2.5.3, Windows 11.

### Intended use

The models score individual network flows (from an uploaded PCAP/CSV or the demo sample) as part of `NetworkAnomalyDetector`. That detector also runs behavior rules over the whole batch. No single model decides on its own; see Fusion below.

### Data and splits

| Split | Flows | Anomalous flows | How it was produced |
|---|---|---|---|
| TRAIN | 28,369 | 2,769 | generator seed 101 |
| CALIBRATION | 28,144 | 2,544 | generator seed 202 |
| TEST | 27,881 | 2,281 | generator seed 303 |

Each split is an independently generated 8-hour "day" (80 hosts, 2 episodes of each anomaly category). No flow, host pairing or episode appears in more than one split. External addresses use the RFC 5737 documentation ranges and DNS names use the reserved `.example` TLD.

Anomaly categories: `port_scan`, `host_sweep`, `brute_force`, `flood`, `bulk_outbound`, `dns_tunneling`, `beaconing`.

### Leakage controls (brief §28)

- **Scaling:** the robust scaler (median/IQR) is fit on TRAIN benign flows only.
- **Unsupervised models:** the Isolation Forest, autoencoder and statistical baseline see only TRAIN benign flows. Labels are used to filter that training data, which assumes a clean baseline. Real baselines rarely are.
- **Thresholds:** every threshold, calibration parameter and the fusion cut is chosen on CALIBRATION. TEST is scored once, at the end.
- **Held-out category:** `beaconing` is withheld from the supervised classifier's TRAIN and CALIBRATION data.
- **Revisions after looking at TEST are recorded, not hidden.** Run 1 used a hand-set fusion cut of 0.4. That let any single layer flag a flow, and TEST showed a fused false-positive rate of 2.88%, about triple any single layer's. The fix was procedural: the cut is now chosen on CALIBRATION like every other threshold. No model, feature or hyperparameter was re-tuned on TEST. The report's `revisions` field records this.

### Features

21 per-flow features (`backend/app/detectors/network/features.py`). Training and serving import the same function, so the features can't drift apart.

- **Counts and rates:** duration, packets and bytes in each direction, bytes/s and packets/s. All are log1p-transformed because they are heavy-tailed.
- **Shape:** mean packet size per direction, forward/backward byte ratio, and a no-response flag.
- **TCP flags:** SYN, RST and FIN ratios.
- **Protocol and port:** protocol flags, plus destination port encoded as service-class flags (web, DNS, auth, mail, ephemeral) rather than a raw number.

There are **no DNS query-name features**. Per-flow layers therefore see a tunnelling query as an ordinary small UDP flow.

### Layers

| Layer | Method | Artifact | Fires when |
|---|---|---|---|
| Statistical | max robust z-score of any feature vs the TRAIN benign baseline | stored in isolation_forest `metadata.json` | p ≤ 0.01 |
| Isolation Forest | scikit-learn `IsolationForest` (200 trees, 256 samples/tree) | `model.onnx` (ONNX) | p ≤ 0.01 |
| Autoencoder | MLP 21-16-6-16-21 (ReLU), reconstruction MSE | `model.onnx` (ONNX) | p ≤ 0.01 |
| Classifier | LightGBM binary, 300 rounds, Platt-calibrated | `model.lgb.txt` (LightGBM text) | calibrated probability ≥ 0.0002 |

The unsupervised layers produce raw scores on incomparable scales. Each score is turned into an **empirical p-value**: the fraction of benign CALIBRATION flows that scored at least as high. That makes the layers comparable, and it gives each alert a plain explanation, such as "higher than 99.9% of benign calibration flows, driven by syn_ratio (+40.6)".

**Why the classifier threshold is 0.0002.** The threshold policy is "lowest threshold with FPR ≤ 1% on CALIBRATION", which spends the whole false-positive budget to maximize recall. On data this separable, the calibrated probability is close to 0 for almost every benign flow, so the cut lands very low. On real traffic, the same policy would land somewhere very different.

**No pickle anywhere.** The ONNX and LightGBM text formats can't run code on load. Every artifact is SHA-256-pinned in its `metadata.json` and checked by `ModelLoader` before loading (`backend/tests/test_model_loader.py`).

**ONNX parity with scikit-learn**, measured on 2,000 TEST flows:
- Isolation Forest: max absolute difference 2.9e-7.
- Autoencoder: max absolute difference 5.6e-6.

### Fusion

A flow's fused score is the noisy-OR of the weights of the layers that fired. The weights are statistical 0.3, Isolation Forest 0.45, autoencoder 0.45 and classifier 0.6. A flow is flagged when the fused score is at least **0.615**, the lowest cut with FPR ≤ 1% on CALIBRATION.

At that cut **no layer can flag a flow alone**. Even the classifier (0.6) needs a second layer to agree. Behavior rules run separately over the batch and can flag the flows they cover.

**Batch verdicts and multiple comparisons.** On CALIBRATION, 0.61% of benign flows reach the cut. A perfectly benign batch of 2,400 flows therefore contains about 15 flagged flows by construction. So model evidence only raises a *batch's* severity when the flagged count is significantly higher than that rate predicts (binomial tail p < 0.001, `backend/app/ml/batch_stats.py`). The alert then says so, for example "37 of 2,400 flagged vs ~14.6 expected by chance". Without this check, every benign upload produced a MEDIUM alert; this is recorded as revision 2 in the report. The flow-level metrics below are unaffected by it. A single-flow event that two layers agree on is reported as LOW, a lead to look at.

### Results on TEST (synthetic)

Flow level: 27,881 flows, 2,281 anomalous.

| | Precision | Recall | F1 | FPR | FNR | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|---|---|
| Statistical | 0.704 | 0.294 | 0.415 | 0.0110 | 0.706 | 0.498 | 0.735 |
| Isolation Forest | 0.467 | 0.099 | 0.163 | 0.0100 | 0.901 | 0.410 | 0.902 |
| Autoencoder | 0.878 | 0.849 | 0.863 | 0.0105 | 0.151 | 0.952 | 0.995 |
| Classifier | 0.890 | 1.000 | 0.942 | 0.0111 | 0.000 | 0.996 | 1.000 |
| **Fused models** | **0.915** | **0.849** | **0.881** | **0.0070** | 0.151 | 0.957 | 0.997 |
| **Fused models + behavior rules** | **0.927** | **1.000** | **0.962** | **0.0070** | 0.000 | n/a | n/a |

Bootstrap 95% intervals for the fused models (1,000 resamples):
- precision 0.903–0.926;
- recall 0.835–0.864;
- F1 0.871–0.891;
- FPR 0.0060–0.0081.

**Recall per category:**

| Category | Statistical | Isolation Forest | Autoencoder | Classifier | Fused models | Fused + rules |
|---|---|---|---|---|---|---|
| port_scan | 0.52 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| host_sweep | 0.25 | 0.16 | 1.00 | 1.00 | 1.00 | 1.00 |
| brute_force | 0.00 | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| flood | 1.00 | 0.79 | 1.00 | 1.00 | 1.00 | 1.00 |
| bulk_outbound | 0.00 | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 |
| dns_tunneling | 0.00 | 0.00 | 0.65 | 1.00 | 0.65 | 1.00 |
| beaconing (held out from classifier) | 0.00 | 0.00 | 0.00 | 1.00 | 0.00 | 1.00 |

**Behavior rules at episode level.** Each rule produced exactly 2 findings on TEST, one per episode of its category (14 of 14 episodes). Every finding covered only flows of its own category, and none was made up of benign flows. On separate benign-only batches generated during development, `bulk_outbound` fired on 6 of 20 batches, triggered by legitimate large cloud uploads. That is why the rule is low-weight and carries no ATT&CK mapping.

**Latency.** Scoring one flow through all four layers on the machine above took 10.7 ms at p50 and 13.2 ms at p95 (n = 500), with one outlier at 123 ms. This includes TreeSHAP contributions for explanations. Latency varies between runs; the report holds the measured values.

### What these results do and don't show

- **The Isolation Forest is weak here** (recall 0.10). Benign DNS flows are as tiny as scan probes, so tree isolation doesn't separate them. Its hyperparameters were fixed before training and were not tuned after seeing this result, because tuning on TEST would be leakage. This is the clearest example in the table of why no single layer decides.
- **The classifier's 1.00 on held-out beaconing is a generator artifact, not generalization.** In this synthetic data, beacons have small responses, like several categories the classifier did see. Real beacons resemble ordinary small HTTPS requests.
- **The fused models miss beaconing and a third of DNS tunnelling.** A single beacon flow looks normal, and per-flow features carry no query-name information. The behavior rules catch both, and that is the reason the rules layer exists.
- **All results come from synthetic data.** Real-traffic performance is unknown until the models are trained and evaluated on a real dataset. The flow parser already reads CICFlowMeter/CIC-IDS2017 CSVs, but the training script can't yet train from them. The plan is to use Monday traffic as the benign baseline, following the leakage-control pattern in [repository-analysis.md](repository-analysis.md) §1.

### Retraining

```bash
backend/.venv/Scripts/python research/experiments/train_network_models.py   # Windows
backend/.venv/bin/python research/experiments/train_network_models.py       # macOS/Linux
```

The script writes new artifacts, recomputes their SHA-256 into `metadata.json`, and rewrites the report. It is deterministic: the same seeds produce identical models and metrics.

---

## Endpoint: fleet baseline and rule layers (v0.1.0)

**Read this first.** There is **no endpoint ML model** in this version; the brief's behavioral Isolation Forest is not implemented. Endpoint detection comes from three rule layers:

- **Host behavior rules** (`BehavioralAnomalyDetector`, thresholds in `detection-rules/custom/endpoint_rules.yaml`), checked against a learned fleet baseline.
- **Sigma rules** (`SigmaDetector`, `detection-rules/sigma/`).
- **Authentication aggregation rules** (`LogDetector`, `detection-rules/custom/auth_rules.yaml`).

Everything below was learned from and measured on **simulated telemetry** from `backend/app/demo/endpoint_sim.py`, so it isn't evidence of real-world performance.

- **Script:** `research/experiments/learn_endpoint_baseline.py`
- **Report:** `research/evaluation/endpoint/report.json`
- **Evaluation date:** 2026-09-24

### The baseline

The baseline records what is normal for the fleet: parent/child process pairs, autostart targets, listening ports and file extensions. It was learned from a benign simulated fleet (40 Windows and 8 Linux hosts, 8 hours, seed 401). Paths are lowercased, and the user-name segment is replaced with `<user>` so that a program learned on one user's machine is recognized on another's.

The baseline is a registered artifact (`json_baseline` format, SHA-256-pinned, loaded by `ModelLoader`). The three rules that need it (`new_persistence_user_writable`, `new_listener_untrusted`, `rare_process_lineage`) report themselves unavailable when it's missing, rather than firing on every AppData autostart.

**A real deployment must learn its own baseline from its own fleet.** The committed one describes simulated hosts.

### Results

**Detection.** 5 independent test fleets (seeds 403–443), one episode of each scenario per fleet. An episode counts as detected when some finding covers at least one of its events.

| Scenario | Host rules | Sigma | Auth rules | Any layer |
|---|---|---|---|---|
| office_spawns_interpreter | 5/5 | 5/5 | 0/5 | 5/5 |
| unsigned_from_user_writable | 5/5 | 5/5 | 0/5 | 5/5 |
| new_persistence_user_writable | 5/5 | 5/5 | 0/5 | 5/5 |
| auth_password_guessing | 0/5 | 0/5 | 5/5 | 5/5 |
| auth_password_spraying | 0/5 | 0/5 | 5/5 | 5/5 |
| mass_file_modification | 5/5 | 0/5 | 0/5 | 5/5 |
| event_log_cleared | 0/5 | 5/5 | 0/5 | 5/5 |
| new_listener_user_writable | 5/5 | 5/5 | 0/5 | 5/5 |
| linux_exec_from_tmp | 5/5 | 5/5 | 0/5 | 5/5 |

**False positives.** Across 10 benign-only fleets (seeds 500–509), each layer raised **0 findings**. That includes the deliberately tricky benign cases in the simulator:
- signed apps that live in AppData (Teams, VS Code, OneDrive);
- signed installers run from Downloads;
- users opening shells;
- one or two mistyped passwords.

### What the evaluation caught during development

- **An osquery normalizer bug** that would have affected real deployments. The first run detected `new_persistence_user_writable` in only 3 of 5 episodes. In osquery's `scheduled_tasks` table, `path` is the task's location in the Task Scheduler library and `action` is the program it runs. The normalizer was reading `path`. It now reads `action`, and there is a regression test for it.
- **A noisy lineage rule.** "Parent/child pair never seen before" fired hundreds of times on benign fleets, because every downloaded installer has a unique name. The rule now also requires the child to lack a trusted signature, so signed installers pass and unsigned programs in user folders don't.

### Limitations

- All numbers come from simulated telemetry, where the simulator defines both normal and anomalous behavior, so they are optimistic.
- osquery's `file_events` have no process ID, so file activity is judged per host, not per process.
- Sigma coverage is only as good as the loaded rules: 8 starter rules ship. The engine loads any Sigma rule file dropped into `detection-rules/sigma/`, and reports the ones it can't support.
- No ML-based endpoint anomaly detection in this version.

---

## Dataset notes for models not yet trained

- **PhiUSIIL (phishing URLs):** label `1` means *legitimate*, the reverse of what you'd guess. Every legitimate URL is an `https://www.<domain>` homepage (100% HTTPS, 0% with a path), while phishing URLs often have paths and plain HTTP. A model trained on whole URLs would score close to 100% here by learning "has a path means phishing", and would then misfire on real deep links. The planned model uses registered-domain features only. The split will be grouped by registered domain, and false positives will be measured separately on realistic legitimate deep links.
- **deepset/prompt-injections:** 546 train / 116 test rows, English and German. That is small, so any metric will carry wide confidence intervals, and the card will show them.
- **SecLists SQLi lists:** attack payloads only. A benign corpus of ordinary form input still has to be chosen, and the model card will describe it.
