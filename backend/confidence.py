"""
Dynamic, multi-dimensional parse confidence (spec #9).

Confidence is **calculated, never hardcoded to 1.0**. Every deterministic family
parse (Android / Linux / Windows) reports a breakdown across the exact pipeline
stages the framework advertises:

    format → pattern → source → parser → semantic → ocsf   (+ field_coverage)

Each sub-score is an honest signal about which stage we are actually sure of:

  * **format**   — did a family format detector match at all (syslog vs logcat vs
                   evtx)? 1.0 for a matched deterministic family, else 0.0.
  * **pattern**  — how completely did the *specific* sub-pattern populate the
                   record envelope (rfc3164 vs rfc5424 vs dmesg …). Scales with
                   structural completeness; floored so a real match is never ~0.
  * **source**   — did we identify the emitting product/service (sshd, kernel,
                   Microsoft-Windows-Security-Auditing …)? Unknown source → 0.6.
  * **parser**   — richness of field extraction (more real fields ⇒ higher trust).
  * **semantic** — did the taxonomy land a confident high-level meaning, i.e. a
                   confident OCSF class, rather than a generic "we parsed it but
                   don't know the class" landing.
  * **ocsf**     — is the OCSF class itself trustworthy (a confident class_uid)?
                   A generic/log-only landing is honestly 0.0 here.

`field_coverage` is filled *after* OCSF mapping (mapped ÷ (mapped+unmapped)) by the
mapper, because only then do we know how much of what we extracted found an OCSF
home vs. was preserved under `unmapped`.

The single scalar `confidence` an event carries is a weighted mean of the stage
sub-scores — so a clean confident auth event approaches 1.0 while a parsed-but-
unclassified line honestly sits lower.
"""
from __future__ import annotations

# OCSF classes we treat as confident semantic landings. Kept in lock-step with
# ``ocsf_mapper._CONFIDENT_OCSF_CLASSES`` (a generic System-Activity / app-Log
# landing is deliberately NOT here → semantic + ocsf sub-scores drop).
CONFIDENT_OCSF_CLASSES = {1007, 3002, 3005, 4001, 4002, 6003}

# Weights for the single scalar aggregate. Sum = 1.0. The parser (extraction) and
# semantic stages carry the most weight; format alone is cheap signal.
_WEIGHTS = {
    "format": 0.10,
    "pattern": 0.15,
    "source": 0.15,
    "parser": 0.25,
    "semantic": 0.20,
    "ocsf": 0.15,
}


def _clamp(x: float) -> float:
    return 0.0 if x < 0.0 else (1.0 if x > 1.0 else x)


def score(
    *,
    format_matched: bool,
    structural_present: int,
    structural_expected: int,
    extracted_fields: int,
    source_known: bool,
    ocsf_class_uid: int,
) -> dict:
    """Compute the stage sub-scores + weighted aggregate for one deterministic parse.

    Args:
      format_matched:      a family format detector matched (True for any family parse).
      structural_present:  how many core envelope slots the sub-pattern actually filled.
      structural_expected: the maximum core envelope slots for that sub-pattern.
      extracted_fields:    total non-empty fields handed to the mapper (envelope + taxonomy).
      source_known:        the emitting product/service was identified (not Unknown/Generic).
      ocsf_class_uid:      the OCSF class the taxonomy landed on.

    Returns a dict of sub-scores plus ``_aggregate`` (the scalar confidence). It does
    NOT include ``field_coverage`` — that is added post-mapping by the OCSF mapper.
    """
    expected = max(int(structural_expected), 1)
    completeness = _clamp(int(structural_present) / expected)
    # Richness rewards extraction beyond the bare envelope (taxonomy-promoted
    # user/ip/port/command fields), so a data-rich line scores above a skeletal one.
    richness = _clamp(int(extracted_fields) / (expected + 3))
    ocsf_confident = int(ocsf_class_uid) in CONFIDENT_OCSF_CLASSES

    sub = {
        "format": 1.0 if format_matched else 0.0,
        # A matched sub-pattern is never below 0.6; completeness lifts it to 1.0.
        "pattern": round(0.6 + 0.4 * completeness, 2),
        "source": 1.0 if source_known else 0.6,
        # A real parse always cleared the bar (0.7); richness lifts it to 1.0.
        "parser": round(0.7 + 0.3 * richness, 2),
        "semantic": 1.0 if ocsf_confident else 0.6,
        "ocsf": 1.0 if ocsf_confident else 0.0,
    }
    agg = sum(sub[k] * w for k, w in _WEIGHTS.items())
    sub["_aggregate"] = round(_clamp(agg), 3)
    return sub


def aggregate(breakdown: dict) -> float:
    """Weighted-mean scalar from an existing stage breakdown (ignores field_coverage)."""
    agg = sum(float(breakdown.get(k, 0.0) or 0.0) * w for k, w in _WEIGHTS.items())
    return round(_clamp(agg), 3)
