"""Scripted demo on synthetic data: legit mail passes, a phishing email is flagged,
a related chat message raises the risk, and quarantine is applied in the mock mailbox."""
from datetime import datetime, timedelta, timezone

from .models import Message

AUTH_PASS = {"Authentication-Results": "mx.examplecorp.com; spf=pass; dkim=pass; dmarc=pass"}
AUTH_ATTACKER = {"Authentication-Results": "mx.examplecorp.com; spf=pass; dkim=none; dmarc=none"}


def run_demo(engine):
    engine.store.reset()
    t0 = datetime.now(timezone.utc) - timedelta(minutes=30)
    steps = []

    legit = Message("email", "priya.nair@examplecorp.com", "Priya Nair", "arjun.rao@examplecorp.com",
                    "Urgent: approve vendor invoice today",
                    "Hi Arjun, the VendorCo invoice needs your approval before end of day. "
                    "It is in the finance portal at https://portal.examplecorp.com/invoices. Thanks, Priya (CFO)",
                    headers=AUTH_PASS, ts=t0)
    r = engine.ingest(legit)
    steps.append({"step": "1. Legitimate urgent mail from the real CFO", "result": r["message"]})

    phish = Message("email", "priya.nair@examplecorp-support.com", "Priya Nair", "arjun.rao@examplecorp.com",
                    "Quick favour, confidential",
                    "Arjun, I am in a meeting and cannot talk. Please keep this between us. "
                    "I need you to review the updated payment details here: https://bit.ly/3PayFix and confirm today.",
                    headers=AUTH_ATTACKER, ts=t0 + timedelta(minutes=10))
    r = engine.ingest(phish)
    steps.append({"step": "2. Impersonation email arrives (scored on its own)", "result": r["message"]})

    chat = Message("chat", "priya.nair", "Priya Nair", "arjun.rao",
                   "", "Hey Arjun, did you see my email? Please check the payment details https://bit.ly/3PayFix urgently.",
                   ts=t0 + timedelta(minutes=14))
    r = engine.ingest(chat)
    steps.append({"step": "3. Related chat message arrives: correlation raises the email's score",
                  "result": r["message"], "rescored": r["updated"]})
    return steps
