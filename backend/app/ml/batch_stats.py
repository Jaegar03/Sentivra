"""Is a batch more anomalous than chance?

Every per-item detector with a calibrated false-positive rate f flags about
n·f items in a perfectly benign batch of n items. Treating "at least one
item flagged" as a batch-level alert therefore guarantees alerts on benign
traffic (the multiple-comparisons problem). This module asks the question
that matters instead: given n items and the benign flag rate measured on
calibration data, how surprising is it to see k or more flagged?
"""

from __future__ import annotations

from dataclasses import dataclass

from scipy.stats import binom

DEFAULT_SIGNIFICANCE = 0.001


@dataclass(frozen=True)
class ExcessTest:
    n: int
    flagged: int
    benign_rate: float
    expected: float
    p_value: float
    significant: bool

    def describe(self) -> str:
        verdict = "significantly more than chance" if self.significant else "consistent with chance"
        return (
            f"{self.flagged} of {self.n} flagged vs ~{self.expected:.1f} expected from benign traffic "
            f"at the calibrated rate {self.benign_rate:.4f} (binomial p={self.p_value:.2g}; {verdict})"
        )


def excess_flags(n: int, flagged: int, benign_rate: float, alpha: float = DEFAULT_SIGNIFICANCE) -> ExcessTest:
    rate = min(max(benign_rate, 1e-9), 1.0)
    p = float(binom.sf(flagged - 1, n, rate)) if flagged > 0 else 1.0
    return ExcessTest(n, flagged, rate, n * rate, p, flagged > 0 and p < alpha)
