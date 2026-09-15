import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy in bits per byte, from 0.0 to 8.0."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def entropy_label(value: float) -> str:
    """Provide a cautious, descriptive label; entropy is not a malware verdict."""
    if value >= 7.2:
        return "Very high"
    if value >= 6.2:
        return "High"
    if value >= 4.0:
        return "Moderate"
    return "Low"
