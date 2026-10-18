"""Heuristic risk engine. Weights/thresholds come from config.json and are
initial, unvalidated values: tune them with eval/run_eval.py."""
import re

from . import features as F

COMPONENTS = ("auth_domain", "url", "sender", "request", "correlation")


def base_components(msg, cfg, seen_senders=frozenset()):
    """Score everything except cross-message correlation."""
    comps, reasons = {}, []
    for name, fn in (
        ("auth_domain", lambda: F.auth_domain(msg, cfg)),
        ("url", lambda: F.url_score(msg, cfg)),
        ("sender", lambda: F.sender_context(msg, cfg, seen_senders)),
        ("request", lambda: F.request_cues(msg, cfg)),
    ):
        s, r = fn()
        comps[name] = s
        reasons += [{"component": name, "code": c, "text": t} for c, t in r]
    return comps, reasons


def combine(comps, cfg):
    w = cfg["weights"]
    return sum(w[k] * comps.get(k, 0.0) for k in COMPONENTS)


def _ident(msg):
    local = msg.sender_addr.split("@")[0].lower()
    name = re.sub(r"[^a-z ]", "", (msg.sender_name or "").lower()).strip()
    return name, re.sub(r"[._-]", "", local)


def correlation(msg, peers, cfg):
    """peers: list of (other_msg, other_base_total). Returns (score, reasons, linked_ids)."""
    c = cfg["correlation"]
    best, reasons, linked = 0.0, [], []
    me_name, me_local = _ident(msg)
    me_urls = {F.registered_domain(F.urlparse(u).hostname or "") for u, _ in F.extract_urls(msg.text, msg.html)}
    me_urls -= set(cfg["trusted_domains"]) | {""}
    me_tok = F.tokens(msg.text)
    for other, other_base in peers:
        if other.id == msg.id or other_base < c["min_peer_base"]:
            continue
        dt = abs((msg.ts - other.ts).total_seconds()) / 60
        if dt > c["window_minutes"]:
            continue
        o_name, o_local = _ident(other)
        o_urls = {F.registered_domain(F.urlparse(u).hostname or "") for u, _ in F.extract_urls(other.text, other.html)}
        score, why = 0.0, []
        n = 0
        if (me_name and me_name == o_name) or (me_local and me_local == o_local):
            score += 0.4
            n += 1
            why.append("same sender identity")
        shared = me_urls & o_urls
        if shared:
            score += 0.4
            n += 1
            why.append(f"shared link domain {sorted(shared)[0]}")
        sim = F.cosine(me_tok, F.tokens(other.text))
        if sim >= c["text_similarity"]:
            score += 0.3
            n += 1
            why.append(f"similar text (cosine {sim:.2f})")
        if n >= c.get("min_indicators", 2):
            linked.append(other.id)
            if score > best:
                best = min(1.0, score)
                reasons = [{"component": "correlation", "code": "RELATED_MESSAGE",
                            "text": f"Related to message #{other.id} ({other.channel}) within {dt:.0f} min: " + ", ".join(why)}]
    return best, reasons, linked


def decide(total, cfg):
    t = cfg["thresholds"]
    if total >= t["quarantine"]:
        return "quarantine"
    if total >= t["flag"]:
        return "flag"
    return "allow"


def score_single(msg, cfg, seen_senders=frozenset()):
    """Single-message score without correlation (used by the evaluation suite)."""
    comps, reasons = base_components(msg, cfg, seen_senders)
    comps["correlation"] = 0.0
    total = combine(comps, cfg)
    return {"components": comps, "total": total, "decision": decide(total, cfg), "reasons": reasons}
