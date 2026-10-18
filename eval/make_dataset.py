"""Generate a SYNTHETIC labelled email set (seeded, template-based).

Results on this set only prove the pipeline runs end to end. They are NOT evidence
of real-world accuracy: replace or extend it with public corpora (see README)."""
import json
import random
import sys
from datetime import datetime, timedelta, timezone

PASS = "mx.examplecorp.com; spf=pass; dkim=pass; dmarc=pass"
FAIL = "mx.examplecorp.com; spf=fail; dkim=fail; dmarc=fail"
PARTIAL = "mx.examplecorp.com; spf=pass; dkim=none; dmarc=none"
KNOWN = [("Priya Nair", "priya.nair@examplecorp.com"), ("Arjun Rao", "arjun.rao@examplecorp.com")]
FIRST = ["Sam", "Maya", "Leo", "Isha", "Tom", "Nina", "Omar", "Zoe"]
LAST = ["Shah", "Brown", "Iyer", "Costa", "Khan", "Lopez", "Wright", "Das"]


def pick(r, xs):
    return xs[r.randrange(len(xs))]


def mk(r, label, kind, name, addr, subject, body, auth, i):
    ts = datetime(2026, 1, 5, 9, tzinfo=timezone.utc) + timedelta(minutes=7 * i)
    headers = {"Authentication-Results": auth} if auth else {}
    return {"channel": "email", "sender_name": name, "sender_addr": addr, "recipient": "arjun.rao@examplecorp.com",
            "subject": subject, "body": body, "headers": headers, "ts": ts.isoformat(), "label": label, "kind": kind}


def benign(r, i):
    k = r.randrange(6)
    if k == 0:
        n, a = pick(r, KNOWN)
        return mk(r, "benign", "colleague", n, a, pick(r, ["Meeting notes", "Roadmap draft", "Lunch?"]),
                  pick(r, ["Notes from today are in the shared folder. Let me know what you think.",
                           "Attaching the draft roadmap for Thursday's review.", "Are you free for lunch tomorrow?"]),
                  PASS, i)
    if k == 1:
        return mk(r, "benign", "vendor_invoice", "VendorCo Accounts", "accounts@vendorco.com",
                  "Invoice " + str(r.randrange(1000, 9999)),
                  "Please find the invoice for this month attached. Payment terms are 30 days. https://billing.vendorco.com/inv",
                  PASS, i)
    if k == 2:
        return mk(r, "benign", "newsletter", "Tech Weekly", "news@techweekly.org", "This week in tech",
                  "Top stories: new chips, open-source releases. Read more: https://techweekly.org/issue/42", PASS, i)
    if k == 3:
        n, a = KNOWN[0]
        return mk(r, "benign", "urgent_cfo", n, a, "Urgent: sign-off needed today",
                  "Arjun, please approve the vendor invoice immediately, the CFO team needs it before end of day. "
                  "Portal: https://portal.examplecorp.com/approve", PASS, i)
    if k == 4:
        n = f"{pick(r, FIRST)} {pick(r, LAST)}"
        return mk(r, "benign", "external_new", n, f"{n.split()[0].lower()}@partnerfirm.com", "Intro and partnership call",
                  "Hello, I'm reaching out about a possible partnership. Could we schedule a call next week?", PASS, i)
    n = f"{pick(r, FIRST)} {pick(r, LAST)}"
    return mk(r, "benign", "forwarded_no_auth", n, f"{n.split()[0].lower()}@universityx.edu", "Conference schedule",
              "Forwarding the conference schedule as discussed. https://universityx.edu/conf", None, i)


def phishing(r, i):
    k = r.randrange(6)
    if k == 0:
        return mk(r, "phishing", "cred_lookalike", "IT Support", "support@examp1ecorp.com", "Verify your account now",
                  "Your password expires today. Verify your account immediately: http://examp1ecorp-login.top/verify", FAIL, i)
    if k == 1:
        return mk(r, "phishing", "bec_lookalike", "Priya Nair", "priya.nair@examplecorp.co", "Confidential request",
                  "I need a wire transfer processed today. Keep this confidential and do not discuss with others. "
                  "Send the bank details to me.", pick(r, [FAIL, PARTIAL]), i)
    if k == 2:
        return mk(r, "phishing", "display_spoof_freemail", "Priya Nair", f"priya.nair{r.randrange(10, 99)}@gmail.com",
                  "Quick task", "Are you at your desk? I need you to buy gift cards for a client urgently. Reply right away.",
                  PASS, i)
    if k == 3:
        return mk(r, "phishing", "shortener_generic", "Delivery Notice", "no-reply@parcel-track.xyz", "Package on hold",
                  "Your parcel is on hold. Confirm delivery within 24 hours: https://bit.ly/parcel" + str(r.randrange(100, 999)),
                  None, i)
    if k == 4:
        return mk(r, "phishing", "compromised_vendor", "VendorCo Accounts", "accounts@vendorco.com", "Updated bank details",
                  "Please note our bank details have changed. Remit all future payments to the new account number below.",
                  PASS, i)
    n = f"{pick(r, FIRST)} {pick(r, LAST)}"
    return mk(r, "phishing", "subtle_new_sender", n, f"{n.split()[0].lower()}@docs-share.com", "Shared document",
              "I shared a document with you. Please sign in to view it: https://docs-share.com/view", PARTIAL, i)


def build(n_each=150, seed=7):
    r = random.Random(seed)
    rows = [benign(r, i) for i in range(n_each)] + [phishing(r, n_each + i) for i in range(n_each)]
    r.shuffle(rows)
    return rows


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "data/synthetic.jsonl"
    with open(out, "w") as f:
        for row in build():
            f.write(json.dumps(row) + "\n")
    print("wrote", out)
