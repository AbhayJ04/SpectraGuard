# Limitations

- Bundled evaluation data is synthetic and template-based. High scores on it do not show real-world accuracy.
  Convert real labelled corpora to the same JSONL format (fields: `channel, sender_name, sender_addr, subject,
  body, headers, ts, label, kind`) and re-run `eval/run_eval.py`. Check each dataset's licence first.
- Weights, thresholds and keyword lists are heuristics. They are not tuned on real traffic.
- SPF/DKIM/DMARC are read from a header; nothing is verified by DNS in this MVP. Headers in test messages are
  supplied by hand. In production the receiving mail server writes this header.
- No public-suffix list: `registered_domain()` is an approximation (handles common `co.uk`-style cases only).
- Lookalike detection uses a small trusted-domain list from `config.json`.
- "Chat" is a simulated channel posted to the same API. There is no Slack/Teams/SMS integration.
- Quarantine only moves a row between folders in SQLite. It is not an integration with any mail platform.
- Correlation is a simple rule (identity, link domain, text similarity inside a time window).
- Rule/keyword features are English-only and can be evaded by rewording. AI-written text is not detected and
  is not used as a signal.
- No authentication on the API and no encryption at rest. Run locally with synthetic data only.
