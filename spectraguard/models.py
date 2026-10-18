from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def parse_ts(value) -> datetime:
    """Parse an ISO-8601 string (or datetime) into an aware UTC datetime."""
    if isinstance(value, datetime):
        dt = value
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass
class Message:
    channel: str                      # "email" or "chat"
    sender_addr: str                  # email address, or chat handle
    sender_name: str = ""
    recipient: str = ""
    subject: str = ""
    body: str = ""
    html: str = ""                    # optional HTML body (used for link-text checks)
    headers: dict = field(default_factory=dict)
    ts: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: Optional[int] = None
    label: Optional[str] = None       # "phishing" / "benign" (analyst or dataset label)

    @property
    def text(self) -> str:
        return f"{self.subject}\n{self.body}".strip()

    @classmethod
    def from_dict(cls, d: dict) -> "Message":
        return cls(
            channel=d.get("channel", "email"),
            sender_addr=d["sender_addr"],
            sender_name=d.get("sender_name", ""),
            recipient=d.get("recipient", ""),
            subject=d.get("subject", ""),
            body=d.get("body", ""),
            html=d.get("html", ""),
            headers=d.get("headers", {}) or {},
            ts=parse_ts(d["ts"]) if d.get("ts") else datetime.now(timezone.utc),
            id=d.get("id"),
            label=d.get("label"),
        )
