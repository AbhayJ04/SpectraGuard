"""Ingest pipeline: store -> score -> correlate -> decide -> (simulated) quarantine."""
import json
import os
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime

from . import scoring
from .models import Message, parse_ts
from .store import Store

DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")


def load_config(path=None):
    with open(path or DEFAULT_CONFIG) as f:
        return json.load(f)


def parse_eml(raw: bytes) -> Message:
    em = BytesParser(policy=policy.default).parsebytes(raw)
    name, addr = parseaddr(str(em.get("From", "")))
    plain = em.get_body(preferencelist=("plain",))
    html = em.get_body(preferencelist=("html",))
    try:
        ts = parse_ts(parsedate_to_datetime(str(em["Date"]))) if em["Date"] else None
    except (TypeError, ValueError):
        ts = None
    headers = {k: str(v) for k, v in em.items() if k.lower() in ("authentication-results", "reply-to")}
    d = {"channel": "email", "sender_addr": addr, "sender_name": name, "recipient": str(em.get("To", "")),
         "subject": str(em.get("Subject", "")), "body": plain.get_content() if plain else "",
         "html": html.get_content() if html else "", "headers": headers}
    if ts:
        d["ts"] = ts
    return Message.from_dict(d)


class Engine:
    def __init__(self, cfg=None, store=None):
        self.cfg = cfg or load_config()
        self.store = store or Store()

    def _seen(self, m):
        known = {k.lower() for k in self.cfg["known_contacts"]}
        return known | ({m.sender_addr.lower()} if self.store.seen_before(m.sender_addr, m.ts, m.id) else set())

    def ingest(self, m: Message) -> dict:
        m.id = self.store.add(m)
        changed = self._rescore_window(m)
        return {"id": m.id, "message": self.get(m.id), "updated": [self.get(i) for i in changed if i != m.id]}

    def _rescore_window(self, anchor: Message):
        win = self.store.within(anchor.ts, self.cfg["correlation"]["window_minutes"])
        base = {}
        for w in win:
            comps, reasons = scoring.base_components(w, self.cfg, self._seen(w))
            comps["correlation"] = 0.0
            base[w.id] = (comps, reasons, scoring.combine(comps, self.cfg))
        changed = []
        for w in win:
            comps, reasons, b = base[w.id]
            peers = [(o, base[o.id][2]) for o in win if o.id != w.id]
            cs, creasons, linked = scoring.correlation(w, peers, self.cfg)
            comps = dict(comps, correlation=cs)
            total = scoring.combine(comps, self.cfg)
            decision = scoring.decide(total, self.cfg)
            old = self.store.row(w.id)
            self.store.save_score(w.id, b, total, decision,
                                  {"components": comps, "reasons": reasons + creasons, "linked": linked,
                                   "weights": self.cfg["weights"]})
            if self.cfg.get("auto_quarantine") and decision == "quarantine" and old["folder"] == "inbox":
                self.store.set_folder(w.id, "quarantine")  # SIMULATED response: mock mailbox only
            if old["score"] is None or abs(old["score"] - total) > 1e-9:
                changed.append(w.id)
        return changed

    def get(self, mid):
        r = self.store.row(mid)
        return Store.public(r) if r else None

    def quarantine(self, mid):
        self.store.set_folder(mid, "quarantine")
        return self.get(mid)

    def release(self, mid):
        self.store.set_folder(mid, "inbox")
        return self.get(mid)

    def label(self, mid, label):
        self.store.set_label(mid, label)
        return self.get(mid)
