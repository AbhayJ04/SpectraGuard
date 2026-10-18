"""Evaluate on a labelled JSONL file: validation/test split, threshold selection on
validation only, baseline comparison, ablation, and a correlation check.

Usage: python -m eval.run_eval [data.jsonl]"""
import copy
import json
import os
import random
import re
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from eval.make_dataset import build  # noqa: E402
from spectraguard import features as F  # noqa: E402
from spectraguard.engine import Engine, load_config  # noqa: E402
from spectraguard.models import Message  # noqa: E402
from spectraguard.scoring import COMPONENTS, score_single  # noqa: E402

MAX_FPR = 0.05  # threshold rule: maximise recall subject to validation FPR <= 5%


def metrics(y, flagged):
    tp = sum(1 for a, b in zip(y, flagged) if a and b)
    fp = sum(1 for a, b in zip(y, flagged) if not a and b)
    fn = sum(1 for a, b in zip(y, flagged) if a and not b)
    tn = sum(1 for a, b in zip(y, flagged) if not a and not b)
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": p, "recall": rc, "fpr": fp / (fp + tn) if fp + tn else 0.0,
            "f1": 2 * p * rc / (p + rc) if p + rc else 0.0, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def auc(y, s):
    pos = [x for a, x in zip(y, s) if a]
    neg = [x for a, x in zip(y, s) if not a]
    if not pos or not neg:
        return 0.0
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def pick_threshold(y, s):
    best = None
    for t in [i / 100 for i in range(1, 100)]:
        m = metrics(y, [x >= t for x in s])
        if m["fpr"] <= MAX_FPR and (best is None or (m["recall"], t) >= (best[0], best[1])):
            best = (m["recall"], t)
    return best[1] if best else 0.99


def baseline_flag(m):
    """Baseline: any auth failure, OR urgency plus a payment/credential request."""
    res = F.parse_auth(m.headers)
    if any(v == "fail" for v in res.values()):
        return True
    t = m.text.lower()
    has = lambda k: re.search(F.REQUEST_PATTERNS[k][1], t) is not None  # noqa: E731
    return has("urgency") and (has("payment") or has("credential"))


def scores(rows, cfg, known):
    out = []
    for r in rows:
        m = Message.from_dict(r)
        out.append(score_single(m, cfg, known)["total"])
    return out


def correlation_check(cfg, n=40, seed=3):
    """Does a related second message (other channel) change the first message's score?"""
    rnd, deltas, crossed = random.Random(seed), [], 0
    for i in range(n):
        e = Engine(cfg=copy.deepcopy(cfg))
        url = f"https://bit.ly/x{rnd.randrange(10**5)}"
        t0 = Message.from_dict({"channel": "email", "sender_name": "Priya Nair", "sender_addr": "priya.nair@examplecorp-support.com",
                                "subject": "Quick favour", "body": f"Please keep this confidential and review the payment details {url} today.",
                                "headers": {"Authentication-Results": "mx; spf=pass; dkim=none; dmarc=none"}, "ts": "2026-01-05T09:00:00+00:00"})
        a = e.ingest(t0)["message"]["score"]
        t1 = Message.from_dict({"channel": "chat", "sender_name": "Priya Nair", "sender_addr": "priya.nair",
                                "body": f"Did you get my email? Check the payment details {url} please.",
                                "ts": (t0.ts + timedelta(minutes=rnd.randrange(1, 30))).isoformat()})
        e.ingest(t1)
        b = e.get(1)["score"]
        deltas.append(b - a)
        crossed += b >= cfg["thresholds"]["quarantine"] > a
    return {"pairs": n, "mean_score_increase": sum(deltas) / n, "pairs_crossing_quarantine": crossed}


def main():
    cfg = load_config()
    known = {k.lower() for k in cfg["known_contacts"]}
    if len(sys.argv) > 1:
        rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    else:
        rows = build()
    random.Random(1).shuffle(rows)
    half = len(rows) // 2
    val, test = rows[:half], rows[half:]
    yv, yt = [r["label"] == "phishing" for r in val], [r["label"] == "phishing" for r in test]

    sv, st = scores(val, cfg, known), scores(test, cfg, known)
    thr = pick_threshold(yv, sv)
    full = metrics(yt, [x >= thr for x in st])
    full["auc"] = auc(yt, st)
    base = metrics(yt, [baseline_flag(Message.from_dict(r)) for r in test])

    abl = {}
    for comp in COMPONENTS[:-1]:
        c2 = copy.deepcopy(cfg)
        c2["weights"][comp] = 0.0
        sv2, st2 = scores(val, c2, known), scores(test, c2, known)
        t2 = pick_threshold(yv, sv2)
        m = metrics(yt, [x >= t2 for x in st2])
        m["auc"], m["threshold"] = auc(yt, st2), t2
        abl[comp] = m

    by_kind = {}
    for r, s in zip(test, st):
        d = by_kind.setdefault(r["kind"], [0, 0])
        d[0] += 1
        d[1] += (s >= thr) == (r["label"] == "phishing")

    report = {"n_val": len(val), "n_test": len(test), "threshold_from_validation": thr,
              "full_model_test": full, "baseline_test": base, "ablation_test": abl,
              "per_kind_accuracy_test": {k: f"{c}/{n}" for k, (n, c) in by_kind.items()},
              "correlation_check": correlation_check(cfg)}
    os.makedirs("eval/out", exist_ok=True)
    with open("eval/out/report.json", "w") as f:
        json.dump(report, f, indent=2)

    pct = lambda x: f"{100 * x:5.1f}%"  # noqa: E731
    print(f"\nTest set: {len(test)} messages | threshold chosen on validation ({len(val)}): {thr:.2f}")
    print(f"{'model':28} {'precision':>9} {'recall':>8} {'FPR':>7} {'F1':>6} {'AUC':>6}")
    print(f"{'SpectraGuard (full)':28} {pct(full['precision']):>9} {pct(full['recall']):>8} {pct(full['fpr']):>7} {full['f1']:6.2f} {full['auc']:6.2f}")
    print(f"{'Baseline (auth fail+keywords)':28} {pct(base['precision']):>9} {pct(base['recall']):>8} {pct(base['fpr']):>7} {base['f1']:6.2f}")
    for k, m in abl.items():
        print(f"{'  without ' + k:28} {pct(m['precision']):>9} {pct(m['recall']):>8} {pct(m['fpr']):>7} {m['f1']:6.2f} {m['auc']:6.2f}")
    print("\nCorrelation check:", report["correlation_check"])
    print("\nNOTE: on the bundled synthetic set these numbers only show the pipeline works; they are not real-world accuracy.")
    print("Report written to eval/out/report.json")


if __name__ == "__main__":
    main()
