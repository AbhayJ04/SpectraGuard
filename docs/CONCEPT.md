# SpectraGuard: concept and structure

## 1. One-paragraph abstract
SpectraGuard is a scoped, explainable phishing-risk scorer. It reads an email (and one simulated chat
channel), extracts verifiable signals (authentication results, domain and URL reputation, sender
context, request language), combines them in one heuristic risk score with reason codes, links related
messages across the two channels, and applies a simulated quarantine in a mock mailbox. A labelled
evaluation suite measures it against a simple baseline before any accuracy claim is made.

## 2. Problem and scope
- Problem: LLMs make fluent, unique phishing cheap, so wording-based filters are weaker, and analysts
  need alerts that are precise and explained.
- In scope (MVP): email ingest, one simulated chat channel, one risk engine, one simulated response,
  evaluation suite.
- Out of scope (future work): live Slack/SMS/voice ingestion, CLIP/visual page analysis, graph anomaly
  detection, vector store, model fine-tuning, analyst-feedback learning, prompt-injection defence,
  real mail-platform integration.
- Not claimed: AI-text "fingerprint" detection (unreliable), novelty, real-world accuracy.

## 3. Pipeline (5 stages)
| Stage | Input | Work | Output |
|---|---|---|---|
| Ingest | `.eml` file or JSON (`email` / `chat`) | Parse headers, body, links; store in SQLite | `Message` row |
| Analyze | Message | Four feature groups (below) | Component scores 0-1 + reasons |
| Correlate | Messages in a 60 min window | Link by sender identity, shared link domain, text similarity (need 2+ indicators, peer must be suspicious) | Correlation score 0-1 |
| Score | Component scores | `Risk = 0.30*Auth/Domain + 0.25*URL + 0.20*Sender + 0.15*Request + 0.10*Correlation` | Total 0-1, decision |
| Act | Decision | allow / flag / quarantine (moves message to quarantine folder of the mock mailbox) | Folder state + audit fields |

## 4. Feature groups (all verifiable, rule-based)
1. Auth & Domain: SPF/DKIM/DMARC from the `Authentication-Results` header, lookalike sender domain
   (edit distance and homoglyph normalisation vs trusted domains), Reply-To mismatch.
2. URL: shorteners, IP hosts, punycode, suspicious TLDs, `@` in URL, link text vs real host mismatch,
   lookalike link domain, login-style paths, no TLS. Static only, no page fetching.
3. Sender context: first contact, display name equal to a known contact but different address,
   authority title in display name of an unknown sender.
4. Request cues: urgency, payment, credential, authority, secrecy language.
5. Correlation: described in section 3.

## 5. Decisions and thresholds
Weights (0.30/0.25/0.20/0.15/0.10) and thresholds (flag 0.30, quarantine 0.50) are INITIAL HEURISTIC
values in `config.json`, not validated. `eval/run_eval.py` picks a threshold on a validation split
(max recall with FPR <= 5%) and reports precision, recall, FPR, F1, AUC on a held-out test split.

## 6. Components and files
```
spectraguard/models.py    Message dataclass
spectraguard/features.py  feature extraction + reasons
spectraguard/scoring.py   combine, correlation, decision
spectraguard/store.py     SQLite mock mailbox (inbox / quarantine)
spectraguard/engine.py    ingest -> score -> correlate -> act; .eml parser
spectraguard/api.py       FastAPI endpoints
spectraguard/static/      single-page UI (no build step)
spectraguard/demo.py      scripted 3-step demo scenario
eval/make_dataset.py      synthetic labelled set generator
eval/run_eval.py          split, thresholds, baseline, ablation, correlation check
tests/                    pytest suite
```

## 7. API
`POST /api/messages` (JSON), `POST /api/messages/eml` (raw .eml), `GET /api/messages?folder=`,
`GET /api/messages/{id}`, `POST /api/messages/{id}/quarantine|release|label`, `POST /api/demo/run`,
`POST /api/reset`, `GET /api/config`.

## 8. Demo script (5 minutes)
1. Run demo: legitimate urgent mail from the real CFO is allowed (score about 0.06).
2. Impersonation email from a lookalike-style domain with a shortened link is flagged on its own (about 0.45).
3. A related chat message with the same link arrives; the email is rescored upward and quarantined (about 0.53).
4. Open the message: component bars and reason codes explain every point of the score.
5. Show `python eval/run_eval.py`: baseline vs full model and ablation.

## 9. Evaluation plan
- Data: labelled benign + phishing emails; bundled synthetic generator for the pipeline check, plus
  public corpora (e.g. Nazario phishing corpus, Enron/SpamAssassin ham) converted to the JSONL format.
- Baseline: any auth failure OR urgency plus payment/credential wording.
- Procedure: validation split picks the threshold; test split reports metrics; ablation removes one
  component at a time; correlation check measures score change on related message pairs.

## 10. Honest limitations
See `docs/LIMITATIONS.md`.
