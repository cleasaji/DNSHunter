"""
Combines per-source DNS query behavior into a single classification:
normal, suspicious, or possible_c2 -- following the pipeline from the
brief (feature extraction -> entropy/frequency/domain analysis ->
detection engine -> verdict).
"""

from typing import Dict, List

from app.models import DnsQuery, Classification
from app.dga_detector import looks_like_dga, dga_score
from app.tunneling_detector import is_tunneling_candidate
from app.beaconing import is_beaconing


def _domain_label(query: str) -> str:
    parts = query.split(".")
    return parts[0] if parts else query


def classify_source(src_ip: str, queries: List[DnsQuery]) -> Classification:
    reasons = []
    score = 0

    dga_hits = [q for q in queries if looks_like_dga(_domain_label(q.query))]
    if len(dga_hits) >= 3:
        reasons.append(f"{len(dga_hits)} queries to algorithmically-generated-looking domains "
                        f"(e.g. {dga_hits[0].query}, score={dga_score(_domain_label(dga_hits[0].query)):.2f})")
        score += 35

    tunneling_hits = [q for q in queries if is_tunneling_candidate(q)]
    if len(tunneling_hits) >= 3:
        reasons.append(f"{len(tunneling_hits)} long, high-entropy queries consistent with DNS tunneling "
                        f"(e.g. {tunneling_hits[0].query[:40]}...)")
        score += 40

    by_domain: Dict[str, List[DnsQuery]] = {}
    for q in queries:
        by_domain.setdefault(q.query, []).append(q)
    beaconing_domains = [d for d, qs in by_domain.items() if is_beaconing(qs)]
    if beaconing_domains:
        reasons.append(f"regular-interval querying of {beaconing_domains} consistent with C2 beaconing")
        score += 30

    score = min(100, score)
    if score >= 60:
        verdict = "possible_c2"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "normal"

    sample = [q.query for q in (dga_hits + tunneling_hits)][:5]

    return Classification(src_ip=src_ip, verdict=verdict, score=score, reasons=reasons, sample_queries=sample)


def classify_all(queries: List[DnsQuery]) -> List[Classification]:
    by_src: Dict[str, List[DnsQuery]] = {}
    for q in queries:
        by_src.setdefault(q.src_ip, []).append(q)
    return [classify_source(src_ip, qs) for src_ip, qs in by_src.items()]
