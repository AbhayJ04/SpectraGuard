"""SQLite-backed mock mail system: inbox + quarantine folders and message history."""
import json
import sqlite3
import threading
from datetime import timedelta

from .models import Message, parse_ts

SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  channel TEXT, sender_addr TEXT, sender_name TEXT, recipient TEXT,
  subject TEXT, body TEXT, html TEXT, headers TEXT, ts TEXT,
  folder TEXT DEFAULT 'inbox',
  base REAL, score REAL, decision TEXT, detail TEXT, label TEXT
);
"""


class Store:
    def __init__(self, path=":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.db.executescript(SCHEMA)

    def reset(self):
        with self.lock:
            self.db.execute("DELETE FROM messages")
            self.db.execute("DELETE FROM sqlite_sequence WHERE name='messages'")
            self.db.commit()

    @staticmethod
    def _msg(row) -> Message:
        return Message(id=row["id"], channel=row["channel"], sender_addr=row["sender_addr"],
                       sender_name=row["sender_name"], recipient=row["recipient"], subject=row["subject"],
                       body=row["body"], html=row["html"], headers=json.loads(row["headers"] or "{}"),
                       ts=parse_ts(row["ts"]), label=row["label"])

    def add(self, m: Message) -> int:
        with self.lock:
            cur = self.db.execute(
                "INSERT INTO messages(channel,sender_addr,sender_name,recipient,subject,body,html,headers,ts,label)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (m.channel, m.sender_addr, m.sender_name, m.recipient, m.subject, m.body, m.html,
                 json.dumps(m.headers), m.ts.isoformat(), m.label))
            self.db.commit()
            return cur.lastrowid

    def get(self, mid: int):
        row = self.db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()
        return self._msg(row) if row else None

    def row(self, mid: int):
        return self.db.execute("SELECT * FROM messages WHERE id=?", (mid,)).fetchone()

    def within(self, ts, minutes):
        lo, hi = (ts - timedelta(minutes=minutes)).isoformat(), (ts + timedelta(minutes=minutes)).isoformat()
        rows = self.db.execute("SELECT * FROM messages WHERE ts BETWEEN ? AND ? ORDER BY ts", (lo, hi)).fetchall()
        return [self._msg(r) for r in rows]

    def seen_before(self, addr, ts, exclude_id):
        r = self.db.execute("SELECT 1 FROM messages WHERE lower(sender_addr)=? AND ts<? AND id!=? LIMIT 1",
                            (addr.lower(), ts.isoformat(), exclude_id)).fetchone()
        return r is not None

    def save_score(self, mid, base, score, decision, detail):
        with self.lock:
            self.db.execute("UPDATE messages SET base=?,score=?,decision=?,detail=? WHERE id=?",
                            (base, score, decision, json.dumps(detail), mid))
            self.db.commit()

    def set_folder(self, mid, folder):
        with self.lock:
            self.db.execute("UPDATE messages SET folder=? WHERE id=?", (folder, mid))
            self.db.commit()

    def set_label(self, mid, label):
        with self.lock:
            self.db.execute("UPDATE messages SET label=? WHERE id=?", (label, mid))
            self.db.commit()

    def list(self, folder=None):
        q, a = "SELECT * FROM messages", ()
        if folder:
            q, a = q + " WHERE folder=?", (folder,)
        return [self.public(r) for r in self.db.execute(q + " ORDER BY ts DESC, id DESC", a).fetchall()]

    @staticmethod
    def public(r):
        d = dict(r)
        d["headers"] = json.loads(d["headers"] or "{}")
        d["detail"] = json.loads(d["detail"]) if d.get("detail") else None
        return d
