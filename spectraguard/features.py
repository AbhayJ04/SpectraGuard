"""Rule-based, verifiable feature extraction. Every feature returns a 0-1 score
plus human-readable reasons. No network calls: SPF/DKIM/DMARC results are read
from the Authentication-Results header written by the receiving mail server."""
import re
from collections import Counter
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "gq", "tk", "ml", "cf", "work", "support", "loan"}
LOGIN_WORDS = ("login", "signin", "verify", "secure", "update", "account", "password")

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
ANCHOR_RE = re.compile(r"<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)

REQUEST_PATTERNS = {
    "urgency": (0.25, r"\b(urgent(ly)?|immediately|asap|right away|within \d+ (hours?|minutes?)|before end of day|final notice|act now)\b"),
    "payment": (0.30, r"\b(wire|transfer|payment|gift cards?|bank details|account number|iban|remit)\b"),
    "credential": (0.35, r"\b(password|passcode|verify your (account|identity)|log ?in|sign ?in|credentials|mfa|2fa|one-time code|otp)\b"),
    "authority": (0.15, r"\b(ceo|cfo|director|president|managing partner|head of finance|legal department)\b"),
    "secrecy": (0.25, r"\b(confidential|do not (tell|share|discuss)|keep this (between us|quiet)|don.t call)\b"),
}


# ---------- helpers ----------
def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered_domain(host: str) -> str:
    """Approximation without a public-suffix list (documented limitation)."""
    labels = [l for l in host.lower().strip(".").split(".") if l]
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in {"co", "com", "org", "gov", "ac", "net"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _normalize(domain: str) -> str:
    d = domain.lower().replace("rn", "m").replace("vv", "w").replace("-", "")
    return d.translate(str.maketrans({"0": "o", "1": "l", "5": "s"}))


def lookalike_of(domain: str, trusted: list):
    """Return the trusted domain this one imitates, or None."""
    domain = domain.lower()
    for t in trusted:
        if domain == t:
            return None
        if _normalize(domain) == _normalize(t) or levenshtein(domain, t) <= 2:
            return t
    return None


def addr_domain(addr: str) -> str:
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def extract_urls(text: str, html: str = ""):
    """Return list of (url, link_text_or_None)."""
    out, seen = [], set()
    for href, label in ANCHOR_RE.findall(html or ""):
        out.append((href.strip(), re.sub(r"<[^>]+>", "", label).strip()))
        seen.add(href.strip())
    for u in URL_RE.findall(f"{text}\n{html or ''}"):
        u = u.rstrip(".,;")
        if u not in seen:
            out.append((u, None))
            seen.add(u)
    return out


def tokens(text: str) -> Counter:
    return Counter(w for w in re.findall(r"[a-z0-9']+", text.lower()) if len(w) > 2)


def cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b[k] for k in a if k in b)
    na = sum(v * v for v in a.values()) ** 0.5
    nb = sum(v * v for v in b.values()) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


# ---------- component 1: authentication & domain ----------
_AUTH_VALUE = {"pass": 0.0, "fail": 1.0, "softfail": 0.7, "temperror": 0.7, "permerror": 0.7}


def parse_auth(headers: dict) -> dict:
    h = next((v for k, v in headers.items() if k.lower() == "authentication-results"), "")
    return dict(re.findall(r"\b(spf|dkim|dmarc)=(\w+)", h.lower()))


def auth_domain(msg, cfg):
    reasons = []
    domain = addr_domain(msg.sender_addr)
    auth_mean = 0.0
    if msg.channel == "email":
        res = parse_auth(msg.headers)
        vals = []
        for k in ("spf", "dkim", "dmarc"):
            r = res.get(k)
            v = _AUTH_VALUE.get(r, 0.4)  # missing/none/neutral -> uncertain
            vals.append(v)
            if v >= 0.7:
                reasons.append((f"{k.upper()}_{(r or 'MISSING').upper()}", f"{k.upper()} result: {r}"))
        if not res:
            reasons.append(("AUTH_MISSING", "No Authentication-Results header; sender not verified"))
        auth_mean = sum(vals) / 3
    look = lookalike_of(domain, cfg["trusted_domains"]) if domain else None
    if look:
        reasons.append(("LOOKALIKE_DOMAIN", f"Sender domain '{domain}' imitates trusted domain '{look}'"))
    rt = next((v for k, v in msg.headers.items() if k.lower() == "reply-to"), "")
    rt_mismatch = bool(rt and addr_domain(rt.split("<")[-1].strip(" >")) not in ("", domain))
    if rt_mismatch:
        reasons.append(("REPLYTO_MISMATCH", "Reply-To domain differs from sender domain"))
    score = min(1.0, 0.5 * auth_mean + 0.6 * (1 if look else 0) + 0.3 * (1 if rt_mismatch else 0))
    return score, reasons


# ---------- component 2: URL analysis (static features only) ----------
def url_score(msg, cfg):
    best, reasons = 0.0, []
    for url, label in extract_urls(msg.text, msg.html):
        p = urlparse(url)
        host = (p.hostname or "").lower()
        if not host:
            continue
        reg = registered_domain(host)
        flags = []
        if reg in cfg["trusted_domains"]:
            continue
        if reg in SHORTENERS:
            flags.append((0.5, "URL_SHORTENER", f"Shortened link ({reg}) hides destination"))
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            flags.append((0.6, "URL_IP_HOST", "Link points to a raw IP address"))
        if "xn--" in host:
            flags.append((0.6, "URL_PUNYCODE", f"Internationalised (punycode) domain: {host}"))
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            flags.append((0.4, "URL_SUSPICIOUS_TLD", f"Suspicious top-level domain: .{host.rsplit('.', 1)[-1]}"))
        if "@" in p.netloc:
            flags.append((0.5, "URL_USERINFO", "URL contains '@' (can disguise the real host)"))
        look = lookalike_of(reg, cfg["trusted_domains"])
        if look:
            flags.append((0.7, "URL_LOOKALIKE", f"Link domain '{reg}' imitates '{look}'"))
        if label and re.match(r"(https?://|www\.)?[\w-]+(\.[\w-]+)+", label):
            shown = urlparse(label if "//" in label else "//" + label).hostname or ""
            if shown and registered_domain(shown) != reg:
                flags.append((0.6, "URL_TEXT_MISMATCH", f"Link text shows '{shown}' but goes to '{host}'"))
        if any(w in url.lower() for w in LOGIN_WORDS):
            flags.append((0.2, "URL_LOGIN_WORDS", "Link path suggests login/verification page"))
        if p.scheme == "http":
            flags.append((0.15, "URL_NO_TLS", "Link does not use HTTPS"))
        s = min(1.0, sum(f[0] for f in flags))
        if s > best:
            best, reasons = s, [(c, t) for _, c, t in flags]
    return best, reasons


# ---------- component 3: sender context ----------
def sender_context(msg, cfg, seen_senders):
    reasons, score = [], 0.0
    addr = msg.sender_addr.lower()
    known = {k.lower(): v for k, v in cfg["known_contacts"].items()}
    name = (msg.sender_name or "").strip().lower()
    if addr not in known and addr not in seen_senders:
        score += 0.35
        reasons.append(("FIRST_CONTACT", "First message from this sender"))
    spoof = [a for a, n in known.items() if name and n.lower() == name and a != addr]
    if spoof:
        score += 0.7
        reasons.append(("DISPLAY_NAME_SPOOF", f"Display name matches known contact {spoof[0]} but address differs"))
    elif addr not in known and re.search(REQUEST_PATTERNS["authority"][1], name):
        score += 0.25
        reasons.append(("TITLE_IN_NAME", "Unknown sender uses an authority title in the display name"))
    return min(1.0, score), reasons


# ---------- component 4: request & content cues ----------
def request_cues(msg, cfg=None):
    text, score, reasons = msg.text.lower(), 0.0, []
    for name, (w, pat) in REQUEST_PATTERNS.items():
        if re.search(pat, text):
            score += w
            reasons.append((f"CUE_{name.upper()}", f"Message contains {name} language"))
    return min(1.0, score), reasons
