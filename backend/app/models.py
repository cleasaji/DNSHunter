from datetime import datetime
from typing import List
from pydantic import BaseModel


class DnsQuery(BaseModel):
    timestamp: datetime
    src_ip: str
    query: str
    query_type: str = "A"


class Classification(BaseModel):
    src_ip: str
    verdict: str
    score: int
    reasons: List[str]
    sample_queries: List[str]
