"""CVSS v3.1 base score calculator (FIRST specification, section 7)."""

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def roundup(value: float) -> float:
    """Spec 'Roundup': smallest number, to one decimal place, >= value (float-safe)."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (math.floor(as_int / 10000) + 1) / 10.0


def parse_vector(vector: str) -> dict:
    parts = vector.split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError(f"not a CVSS:3.1 vector: {vector!r}")
    metrics = {}
    for part in parts[1:]:
        key, _, val = part.partition(":")
        metrics[key] = val
    for key in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        if key not in metrics:
            raise ValueError(f"missing metric {key} in {vector!r}")
    return metrics


def base_score(vector: str) -> float:
    m = parse_vector(vector)
    try:
        changed = m["S"] == "C"
        if m["S"] not in ("U", "C"):
            raise KeyError(m["S"])
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        if changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        exploitability = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError as exc:
        raise ValueError(f"invalid metric value {exc} in {vector!r}") from None
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity(score: float) -> str:
    if score == 0:
        return "INFO"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"
