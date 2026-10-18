import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from datetime import datetime, timedelta, timezone

from spectraguard import features as F
from spectraguard.demo import run_demo
from spectraguard.engine import Engine, load_config, parse_eml
from spectraguard.models import Message
from spectraguard.scoring import score_single

CFG = load_config()
KNOWN = {k.lower() for k in CFG["known_contacts"]}
SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample")


def msg(**k):
    base = dict(channel="email", sender_addr="x@example.org", ts=datetime.now(timezone.utc))
    base.update(k)
    return Message(**base)


def test_weights_sum_to_one():
    assert abs(sum(CFG["weights"].values()) - 1.0) < 1e-9


def test_levenshtein_and_lookalike():
    assert F.levenshtein("kitten", "sitting") == 3
    assert F.lookalike_of("examp1ecorp.com", ["examplecorp.com"]) == "examplecorp.com"
    assert F.lookalike_of("examplecorp.com", ["examplecorp.com"]) is None
    assert F.lookalike_of("unrelated.org", ["examplecorp.com"]) is None


def test_auth_parsing():
    assert F.parse_auth({"Authentication-Results": "mx; spf=pass; dkim=fail; dmarc=none"}) == {"spf": "pass", "dkim": "fail", "dmarc": "none"}


def test_url_features():
    m = msg(body="go to https://bit.ly/abc now")
    assert F.url_score(m, CFG)[0] >= 0.5
    m = msg(body="see https://portal.examplecorp.com/x")
    assert F.url_score(m, CFG)[0] == 0.0
    m = msg(html='<a href="http://evil.top/login">https://examplecorp.com</a>')
    codes = [c for c, _ in F.url_score(m, CFG)[1]]
    assert "URL_TEXT_MISMATCH" in codes


def test_display_name_spoof():
    m = msg(sender_name="Priya Nair", sender_addr="priya@gmail.com")
    s, r = F.sender_context(m, CFG, set())
    assert s >= 0.7 and any(c == "DISPLAY_NAME_SPOOF" for c, _ in r)


def test_legit_sample_allowed_and_phish_sample_quarantined():
    legit = parse_eml(open(os.path.join(SAMPLES, "legit_cfo.eml"), "rb").read())
    phish = parse_eml(open(os.path.join(SAMPLES, "phish_lookalike.eml"), "rb").read())
    assert score_single(legit, CFG, KNOWN)["decision"] == "allow"
    assert score_single(phish, CFG, KNOWN)["decision"] == "quarantine"


def test_correlation_raises_score_and_quarantines():
    steps = run_demo(Engine())
    email, rescored = steps[1]["result"], steps[2]["rescored"]
    assert email["decision"] == "flag" and email["folder"] == "inbox"
    assert rescored and rescored[0]["score"] > email["score"]
    assert rescored[0]["decision"] == "quarantine" and rescored[0]["folder"] == "quarantine"


def test_unrelated_message_does_not_correlate():
    e = Engine()
    t = datetime.now(timezone.utc)
    e.ingest(Message("email", "a@evil.top", "Bob", subject="hi", body="verify your password https://bit.ly/q", ts=t))
    r = e.ingest(Message("email", "c@other.org", "Carol", subject="lunch", body="Want to grab lunch?", ts=t + timedelta(minutes=5)))
    assert r["message"]["detail"]["components"]["correlation"] == 0.0


def test_api_flow():
    from fastapi.testclient import TestClient
    from spectraguard import api
    c = TestClient(api.app)
    c.post("/api/reset")
    r = c.post("/api/messages", json={"sender_addr": "evil@examp1ecorp.com", "subject": "Verify your account",
                                       "body": "Verify your password immediately http://examp1ecorp.top/login",
                                       "headers": {"Authentication-Results": "mx; spf=fail; dkim=fail; dmarc=fail"}}).json()
    assert r["message"]["decision"] == "quarantine"
    mid = r["id"]
    assert c.get("/api/messages?folder=quarantine").json()[0]["id"] == mid
    assert c.post(f"/api/messages/{mid}/release").json()["folder"] == "inbox"
    assert c.post(f"/api/messages/{mid}/label", json={"label": "phishing"}).json()["label"] == "phishing"
    assert c.get("/api/messages/999").status_code == 404
    assert c.get("/").status_code == 200
