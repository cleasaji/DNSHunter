"""
DNS-layer beaconing: a source repeatedly querying the same domain at a
near-constant interval, the DNS equivalent of the network-layer
beaconing pattern used elsewhere in this portfolio (see NetTrace) --
malware doing periodic "check in" resolution before connecting.
"""

import statistics
from typing import List

from app.models import DnsQuery

MIN_QUERIES = 5
MAX_COEFFICIENT_OF_VARIATION = 0.2


def is_beaconing(queries: List[DnsQuery]) -> bool:
    if len(queries) < MIN_QUERIES:
        return False
    timestamps = sorted(q.timestamp for q in queries)
    intervals = [(b - a).total_seconds() for a, b in zip(timestamps, timestamps[1:])]
    if not intervals or statistics.mean(intervals) == 0:
        return False
    cov = statistics.pstdev(intervals) / statistics.mean(intervals)
    return cov <= MAX_COEFFICIENT_OF_VARIATION
