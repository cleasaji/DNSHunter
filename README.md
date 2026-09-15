# 🧬 DNSHunter — DNS-Based C2 Detection System

A FastAPI service that classifies DNS query streams per source IP as
**normal / suspicious / possible_c2**, using three real, independently
verified detection techniques: bigram-frequency DGA scoring, entropy-
based tunneling detection, and beaconing-interval analysis.

```
Normal DNS
     |
Feature Extraction
     |
Entropy + Frequency + Domain Analysis
     |
Detection Engine
     |
Normal / Suspicious / Possible C2
```

---

## Run it yourself

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Or open `frontend/index.html` -- it ships with a mixed normal/malicious
sample payload pre-filled, so clicking Classify immediately shows both verdicts.

## A real DGA detector, calibrated against its own output

`dga_detector.py` builds a bigram-frequency table from a small
reference corpus of legitimate domain words and scores a candidate
label by its average bigram log-likelihood. I calibrated the decision
threshold by actually measuring the score distributions rather than
guessing:

```
real words (google, microsoft, banking, ...):  avg score ~= -5.6
random 12-char strings:                          avg score ~= -7.2
```

`DGA_SCORE_THRESHOLD = -6.2` sits in the gap between those two
distributions -- a real, measured calibration, not a placeholder number.

## Two other independently-testable signals

- **`tunneling_detector.py`** -- flags queries that are both long (>=50
  chars) and high-entropy (>=3.5 bits/char), or use a tunneling-favored
  record type (TXT/NULL/CNAME) with moderately high entropy.
- **`beaconing.py`** -- the same near-constant-interval signature used
  elsewhere in this portfolio (NetTrace), applied to repeated DNS
  queries for the same domain instead of network connections.

`engine.py` combines all three per source IP into a scored, reasoned
verdict -- each contributing signal is named in the response, not just a
number.

## Tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

10 tests: DGA scoring correctly ranking real words above random
strings, the calibrated threshold correctly classifying both, tunneling
detection on a real long/high-entropy query vs. a normal one, beaconing
on regular vs. irregular intervals, and the combined classification
engine correctly scoring ordinary browsing as "normal" and a
DGA+tunneling pattern as "suspicious"/"possible_c2".

## Project layout

```
backend/
  app/
    models.py, dga_detector.py, tunneling_detector.py, beaconing.py
    engine.py, main.py
  tests/
    test_dnshunter.py
frontend/
  index.html
```

## Honest scope

The DGA reference corpus is ~60 hand-picked words, not a large labeled
dataset -- good enough to demonstrate and validate the bigram-scoring
*technique* (and its calibration is genuinely measured, shown above),
but a production deployment would train the same bigram model (or a
proper Markov-chain/LSTM DGA classifier) on a much larger corpus. The
detection logic itself -- entropy, frequency, and interval analysis --
is real and independently tested.
