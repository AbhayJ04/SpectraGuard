# SpectraGuard MVP

Explainable phishing risk scoring for email plus one simulated chat channel, with a mock mailbox and a
simulated quarantine action. Runs locally on synthetic data. See `docs/CONCEPT.md` for the design and
`docs/LIMITATIONS.md` for what this does not do.

## Run
```bash
python3 -m venv .venv && source .venv/bin/activate     # optional
pip install -r requirements.txt
python -m spectraguard                                  # UI + API at http://127.0.0.1:8000
```
Open the page, click **Run demo scenario**, then select messages to see component scores and reasons.

## Score your own email
```bash
curl -X POST --data-binary @data/sample/phish_lookalike.eml http://127.0.0.1:8000/api/messages/eml
```

## Tests and evaluation
```bash
python -m pytest -q tests
python eval/run_eval.py                  # synthetic set: pipeline check only
python eval/make_dataset.py my.jsonl     # write the synthetic set to a file
python eval/run_eval.py my.jsonl         # or evaluate your own labelled JSONL
```
`eval/run_eval.py` chooses the threshold on a validation split, then reports precision, recall, false-positive
rate, F1 and AUC on a held-out test split, against a baseline and with each component removed. Copy a chosen
threshold into `config.json` by hand if you want to use it.

## Configuration
`config.json`: trusted domains, known contacts, weights, thresholds, correlation window. Weights and
thresholds are initial heuristic values, not validated.

## Layout
```
spectraguard/   engine, features, scoring, store, API, UI, demo
eval/           dataset generator and evaluation suite
tests/          pytest suite
data/sample/    two example .eml files
docs/           CONCEPT.md, LIMITATIONS.md
```
