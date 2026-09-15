from dataclasses import dataclass
from pe_parser import PEInfo
from signatures import SIGNATURES

@dataclass
class Evidence:
    description: str
    points: int
    kind: str

@dataclass
class Fingerprint:
    name: str
    score: int
    confidence: str
    evidence: list[Evidence]


def confidence(score: int, marker_count: int, section_count: int) -> str:
    """Calibrate confidence so one marker alone is not treated as proof."""
    if marker_count and section_count and score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"


def fingerprint(info: PEInfo) -> list[Fingerprint]:
    names = {section.name.lower(): section.name for section in info.sections}
    data = info.data.lower()
    results = []
    for name, rule in SIGNATURES.items():
        score = 0
        evidence = []
        marker_count = 0
        section_count = 0
        for marker, points, description in rule["markers"]:
            if marker.lower() in data:
                score += points
                marker_count += 1
                evidence.append(Evidence(description, points, "marker"))
        for expected, points in rule["sections"].items():
            actual = names.get(expected.lower())
            if actual:
                score += points
                section_count += 1
                evidence.append(Evidence(f"Section found: {actual}", points, "section"))
        if score:
            results.append(Fingerprint(name, min(score, 100), confidence(score, marker_count, section_count), evidence))
    return sorted(results, key=lambda item: item.score, reverse=True)
