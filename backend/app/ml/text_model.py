"""LinearTextModel: a hashed-n-gram TF-IDF + logistic regression classifier
with Platt calibration, stored without pickle.

Why not just joblib-dump the sklearn Pipeline: unpickling runs arbitrary
code, so a pickled model is only as trustworthy as every hand that touched
the file. This model's entire state is a few numeric arrays (IDF weights,
coefficients, intercept, calibration parameters) plus JSON config for the
vectorizers. HashingVectorizer is stateless, so it can be rebuilt from its
parameters, and everything else is plain arithmetic. The artifact is a
.npz loaded with allow_pickle=False.

The training scripts in research/experiments/ fit the equivalent sklearn
pipeline, export it with `LinearTextModel.from_sklearn(...)`, and assert
that both give the same predictions before writing the artifact.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import HashingVectorizer


@dataclass(frozen=True)
class VectorizerSpec:
    analyzer: str             # "char", "char_wb" or "word"
    ngram_min: int
    ngram_max: int
    n_features: int

    def build(self) -> HashingVectorizer:
        return HashingVectorizer(
            analyzer=self.analyzer,
            ngram_range=(self.ngram_min, self.ngram_max),
            n_features=self.n_features,
            alternate_sign=False,
            norm=None,
            lowercase=False,  # callers pass text that's already normalized
            token_pattern=r"(?u)\b\w+\b" if self.analyzer == "word" else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "analyzer": self.analyzer,
            "ngram_min": self.ngram_min,
            "ngram_max": self.ngram_max,
            "n_features": self.n_features,
        }


def hashed_features(specs: Sequence[VectorizerSpec], docs: Sequence[str]) -> sp.csr_matrix:
    """Raw hashed n-gram counts, one block per vectorizer, concatenated."""
    blocks = [spec.build().transform(docs) for spec in specs]
    return sp.hstack(blocks, format="csr")


def tfidf(counts: sp.csr_matrix, idf: np.ndarray) -> sp.csr_matrix:
    """Same arithmetic as TfidfTransformer(sublinear_tf=True, norm="l2")."""
    x = counts.astype(np.float64).tocsr(copy=True)
    np.log(x.data, out=x.data)
    x.data += 1.0
    x = x @ sp.diags(idf.astype(np.float64))
    norms = np.sqrt(np.asarray(x.multiply(x).sum(axis=1)).ravel())
    norms[norms == 0.0] = 1.0
    return sp.csr_matrix(sp.diags(1.0 / norms) @ x)


class LinearTextModel:
    def __init__(
        self,
        *,
        specs: Sequence[VectorizerSpec],
        idf: np.ndarray,
        coef: np.ndarray,
        intercept: float,
        platt_a: float,
        platt_b: float,
    ) -> None:
        self.specs = list(specs)
        self.idf = idf
        self.coef = coef
        self.intercept = float(intercept)
        self.platt_a = float(platt_a)
        self.platt_b = float(platt_b)

    # ---- inference ---------------------------------------------------------

    def decision_function(self, docs: Sequence[str]) -> np.ndarray:
        x = tfidf(hashed_features(self.specs, docs), self.idf)
        return x @ self.coef.astype(np.float64) + self.intercept

    def predict_proba(self, docs: Sequence[str]) -> np.ndarray:
        """Calibrated probability of the positive (malicious) class."""
        d = self.decision_function(docs)
        return 1.0 / (1.0 + np.exp(-(self.platt_a * d + self.platt_b)))

    def top_ngrams(self, doc: str, k: int = 5) -> list[tuple[str, float]]:
        """The n-grams in `doc` that pushed the score toward malicious the
        most. Hashing is one-way, so this re-derives the n-grams from the
        document itself and looks up each one's weight."""
        contributions: dict[str, float] = {}
        offset = 0
        x = tfidf(hashed_features(self.specs, [doc]), self.idf).toarray().ravel()
        for spec in self.specs:
            grams = sorted(set(spec.build().build_analyzer()(doc)))
            for gram, col in zip(grams, _hash_indices(spec, grams), strict=True):
                value = x[offset + col] * float(self.coef[offset + col])
                if value > 0:
                    contributions[gram] = max(contributions.get(gram, 0.0), value)
            offset += spec.n_features
        return sorted(contributions.items(), key=lambda kv: kv[1], reverse=True)[:k]

    # ---- persistence -------------------------------------------------------

    def save(self, path: Path) -> None:
        np.savez_compressed(
            path,
            idf=self.idf.astype(np.float32),
            coef=self.coef.astype(np.float32),
            intercept=np.array([self.intercept], dtype=np.float64),
            platt=np.array([self.platt_a, self.platt_b], dtype=np.float64),
        )

    @classmethod
    def load(cls, path: Path, specs: Sequence[VectorizerSpec]) -> LinearTextModel:
        with np.load(path, allow_pickle=False) as arrays:
            expected = sum(s.n_features for s in specs)
            if arrays["coef"].shape != (expected,):
                raise ValueError(
                    f"Model has {arrays['coef'].shape[0]} coefficients but the "
                    f"vectorizer config produces {expected} features"
                )
            return cls(
                specs=specs,
                idf=arrays["idf"],
                coef=arrays["coef"],
                intercept=float(arrays["intercept"][0]),
                platt_a=float(arrays["platt"][0]),
                platt_b=float(arrays["platt"][1]),
            )

    @classmethod
    def from_sklearn(cls, *, specs, tfidf_transformer, classifier, platt_a, platt_b) -> LinearTextModel:
        return cls(
            specs=specs,
            idf=np.asarray(tfidf_transformer.idf_, dtype=np.float64),
            coef=np.asarray(classifier.coef_, dtype=np.float64).ravel(),
            intercept=float(np.asarray(classifier.intercept_).ravel()[0]),
            platt_a=platt_a,
            platt_b=platt_b,
        )


def _hash_indices(spec: VectorizerSpec, grams: Sequence[str]) -> list[int]:
    """Column index of each n-gram. HashingVectorizer hashes analyzer output
    with a FeatureHasher(input_type="string"), so the same hasher applied
    to one n-gram per row gives the same columns."""
    if not grams:
        return []
    from sklearn.feature_extraction import FeatureHasher

    hasher = FeatureHasher(n_features=spec.n_features, input_type="string", alternate_sign=False)
    return [int(i) for i in hasher.transform([[g] for g in grams]).indices]
