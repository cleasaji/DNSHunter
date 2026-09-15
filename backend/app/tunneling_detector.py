"""
DNS tunneling detection: long, high-entropy query labels (encoded
payload data) plus TXT/NULL record types (common tunneling protocol
choices, since they carry more arbitrary data than an A record).
"""

import math
from collections import Counter

from app.models import DnsQuery

LENGTH_THRESHOLD = 50
ENTROPY_THRESHOLD = 3.5
TUNNELING_RECORD_TYPES = {"TXT", "NULL", "CNAME"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_tunneling_candidate(query: DnsQuery) -> bool:
    label = query.query.split(".")[0] if query.query else ""
    long_and_random = len(query.query) >= LENGTH_THRESHOLD and shannon_entropy(label) >= ENTROPY_THRESHOLD
    suspicious_record = query.query_type in TUNNELING_RECORD_TYPES
    return long_and_random or (suspicious_record and shannon_entropy(label) >= ENTROPY_THRESHOLD - 0.5)
