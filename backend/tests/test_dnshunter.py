import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models import DnsQuery
from app.dga_detector import dga_score, looks_like_dga
from app.tunneling_detector import is_tunneling_candidate
from app.beaconing import is_beaconing
from app.engine import classify_source, classify_all

BASE = datetime(2026, 9, 1, 10, 0, 0)


def test_real_words_score_higher_than_random_strings():
    assert dga_score("microsoft") > dga_score("xqzvbkpjmn")


def test_looks_like_dga_true_for_random_string():
    assert looks_like_dga("kx7qz2p9mw3lts6vbn8j1r5hy0adfe4c")


def test_looks_like_dga_false_for_common_word():
    assert not looks_like_dga("banking")


def test_tunneling_candidate_flags_long_high_entropy_query():
    q = DnsQuery(timestamp=BASE, src_ip="10.0.0.5",
                 query="kx7qz2p9mw3lts6vbn8j1r5hy0adfe4c9plmnqrstuv.exfil.example.com", query_type="A")
    assert is_tunneling_candidate(q)


def test_tunneling_candidate_not_flagged_for_normal_query():
    q = DnsQuery(timestamp=BASE, src_ip="10.0.0.5", query="www.google.com", query_type="A")
    assert not is_tunneling_candidate(q)


def test_beaconing_detected_for_regular_interval_queries():
    queries = [
        DnsQuery(timestamp=BASE + timedelta(seconds=60 * i), src_ip="10.0.0.5", query="c2.example.net")
        for i in range(6)
    ]
    assert is_beaconing(queries)


def test_beaconing_not_flagged_for_irregular_queries():
    offsets = [0, 5, 340, 12, 900, 33]
    queries = [
        DnsQuery(timestamp=BASE + timedelta(seconds=o), src_ip="10.0.0.5", query="normal.example.com")
        for o in offsets
    ]
    assert not is_beaconing(queries)


def test_classify_source_normal_for_ordinary_browsing():
    queries = [
        DnsQuery(timestamp=BASE + timedelta(seconds=30 * i), src_ip="10.0.0.9", query=d)
        for i, d in enumerate(["www.google.com", "mail.google.com", "docs.google.com", "www.github.com"])
    ]
    result = classify_source("10.0.0.9", queries)
    assert result.verdict == "normal"
    assert result.score < 30


def test_classify_source_possible_c2_for_dga_plus_tunneling():
    dga_queries = [
        DnsQuery(timestamp=BASE + timedelta(seconds=i), src_ip="10.0.0.77",
                 query=f"kx7qz2p9mw{i}lts6vbn8j1r5hy0adfe4c.badcdn.net")
        for i in range(4)
    ]
    result = classify_source("10.0.0.77", dga_queries)
    assert result.verdict in ("suspicious", "possible_c2")
    assert result.score >= 30


def test_classify_all_groups_by_source_ip():
    queries = [
        DnsQuery(timestamp=BASE, src_ip="10.0.0.1", query="www.google.com"),
        DnsQuery(timestamp=BASE, src_ip="10.0.0.2", query="www.wikipedia.org"),
    ]
    results = classify_all(queries)
    assert {r.src_ip for r in results} == {"10.0.0.1", "10.0.0.2"}
