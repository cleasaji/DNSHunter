from typing import List
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.models import DnsQuery, Classification
from app.engine import classify_all

app = FastAPI(title="DNSHunter", description="DNS-based C2 detection system.", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.post("/classify", response_model=List[Classification])
def classify(queries: List[DnsQuery]):
    return classify_all(queries)


@app.get("/health")
def health():
    return {"status": "ok"}
