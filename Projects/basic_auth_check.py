#!/usr/bin/env python3
"""
basic_auth_check.py — quiet default-credential checker for common web servers.

Modules: generic HTTP Basic-auth, Apache Tomcat Manager, Jenkins.
Tries a *small* curated list of default credentials WITHOUT tripping account
lockouts or rate limiting.

Use only against hosts you own or are explicitly authorized to test.

Anti-lockout design:
  - Password-spray ordering: usernames are interleaved so the same account is never
    hit twice in a row (lockout counters are per-account).
  - Hard cap on attempts per account (default 3 — most policies lock at 5).
  - Single-threaded, with a delay + random jitter between every request.
  - Backs off on 429 / 503 / Retry-After and on "locked/too many" response bodies.
  - Honors a per-request timeout so a dead port can't hang the run.
"""

import sys
import time
import random
from datetime import datetime

try:
    import requests
    from requests.auth import HTTPBasicAuth
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] Missing dependency. Install with:  pip install requests")

LOCKOUT_HINTS = ("locked", "too many", "rate limit", "try again later", "temporarily")

# --- Curated credential lists. Edit freely; keep them short on purpose. ---
GENERIC_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""), ("admin", "123456"),
    ("root", "root"), ("root", "toor"), ("administrator", "administrator"),
    ("guest", "guest"), ("user", "user"),
]
TOMCAT_CREDS = [
    ("tomcat", "tomcat"), ("tomcat", "s3cret"), ("admin", "admin"),
    ("admin", "tomcat"), ("role1", "role1"), ("both", "tomcat"),
    ("manager", "manager"), ("admin", ""),
]
JENKINS_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", ""),
    ("jenkins", "jenkins"), ("admin", "jenkins"), ("user", "password"),
]


# --------------------------------------------------------------------------- #
# Attempt functions: return (kind, code, extra)
#   kind: "success" | "partial" | "fail" | "backoff" | "error"
#   extra: seconds to wait (backoff) or message (error), else None
# --------------------------------------------------------------------------- #
def _ratelimited(r):
    body = (r.text or "").lower()
    if r.status_code in (429, 503) or any(h in body for h in LOCKOUT_HINTS):
        return int(r.headers.get("Retry-After", "60") or 60)
    return None


def attempt_basic(session, url, user, pw, timeout):
    """HTTP Basic auth (generic + Tomcat).
    401 = bad creds; 403 = valid creds but lacking role; 2xx/3xx = access."""
    try:
        r = session.get(url, auth=HTTPBasicAuth(user, pw), timeout=timeout,
                        verify=False, allow_redirects=False)
    except requests.RequestException as e:
        return ("error", None, str(e))
    wait = _ratelimited(r)
    if wait is not None:
        return ("backoff", r.status_code, wait)
    if r.status_code == 401:
        return ("fail", r.status_code, None)
    if r.status_code == 403:
        return ("partial", r.status_code, None)   # authenticated, no permission
    if r.status_code < 500:
        return ("success", r.status_code, None)
    return ("fail", r.status_code, None)


def attempt_jenkins(session, url, user, pw, timeout):
    """Jenkins form login. POST to /j_spring_security_check; success = 302 that
    does NOT redirect back to loginError."""
    session.cookies.clear()   # keep each attempt independent
    data = {"j_username": user, "j_password": pw, "from": "/", "Submit": "Sign in"}
    try:
        r = session.post(url, data=data, timeout=timeout, verify=False,
                         allow_redirects=False)
    except requests.RequestException as e:
        return ("error", None, str(e))
    wait = _ratelimited(r)
    if wait is not None:
        return ("backoff", r.status_code, wait)
    loc = r.headers.get("Location", "").lower()
    if r.status_code in (302, 303) and "loginerror" not in loc:
        return ("success", r.status_code, None)
    return ("fail", r.status_code, None)


MODULES = {
    "generic": {"auth": attempt_basic,   "path": "/",
                "creds": GENERIC_CREDS,  "desc": "Generic HTTP Basic-auth"},
    "tomcat":  {"auth": attempt_basic,   "path": "/manager/html",
                "creds": TOMCAT_CREDS,   "desc": "Apache Tomcat Manager"},
    "jenkins": {"auth": attempt_jenkins, "path": "/j_spring_security_check",
                "creds": JENKINS_CREDS,  "desc": "Jenkins form login"},
}


# --------------------------------------------------------------------------- #
def ask(prompt, default=None):
    suffix = f" [{default}]" if default not in (None, "") else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val or (default if default is not None else "")


def spray_order(pairs, max_per_user):
    """Interleave usernames (round-robin) and cap attempts per account."""
    buckets = {}
    for u, p in pairs:
        buckets.setdefault(u, []).append((u, p))
    for u in buckets:
        buckets[u] = buckets[u][:max_per_user]
    ordered, users = [], list(buckets.keys())
    while any(buckets[u] for u in users):
        for u in users:
            if buckets[u]:
                ordered.append(buckets[u].pop(0))
    return ordered


def fingerprint(session, base, timeout):
    """Best-effort module guess from the Server banner / X-Jenkins header / body."""
    try:
        r = session.get(base, timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None
    server = r.headers.get("Server", "").lower()
    body = (r.text or "").lower()
    if "x-jenkins" in {k.lower() for k in r.headers} or "jenkins" in body:
        return "jenkins"
    if "tomcat" in server or "coyote" in server or "apache tomcat" in body:
        return "tomcat"
    return None


def main():
    dry_run = "--dry-run" in sys.argv

    print("=" * 60)
    print(" Web server default-credential checker")
    print("=" * 60)

    ok = ask("Are you authorized to test this target? (yes/no)", "no").lower()
    if ok not in ("y", "yes"):
        sys.exit("[!] Aborted. Only test hosts you are authorized to test.")

    host = ask("Target IP / host")
    if not host:
        sys.exit("[!] No target given.")
    port = ask("Port", "80")
    https = ask("Use HTTPS? (y/N)", "n").lower() in ("y", "yes")
    scheme = "https" if https else "http"
    base = f"{scheme}://{host}:{port}"

    session = requests.Session()

    # Suggest a module from a quick fingerprint, but always let the user override.
    guess = None if dry_run else fingerprint(session, base + "/", 6)
    if guess:
        print(f"[*] Fingerprint suggests: {guess} ({MODULES[guess]['desc']})")
    default_mod = guess or "generic"
    choice = ask(f"Module ({'/'.join(MODULES)})", default_mod).lower()
    if choice not in MODULES:
        sys.exit(f"[!] Unknown module '{choice}'. Choose one of: {', '.join(MODULES)}")
    module = MODULES[choice]

    path = ask("Path", module["path"])
    if not path.startswith("/"):
        path = "/" + path
    url = base + path

    delay = float(ask("Delay between attempts (seconds)", "3"))
    cap = int(ask("Max attempts per account", "3"))
    timeout = float(ask("Per-request timeout (seconds)", "8"))

    attempts = spray_order(module["creds"], cap)
    logfile = f"cred_check_{choice}_{host}_{datetime.now():%Y%m%d_%H%M%S}.log"

    print(f"\n[*] Module : {choice} ({module['desc']})")
    print(f"[*] Target : {url}")
    print(f"[*] Trying : {len(attempts)} credentials (spray order, cap {cap}/account)")
    print(f"[*] Pacing : {delay}s + jitter between attempts")
    print(f"[*] Log    : {logfile}\n")

    if dry_run:
        for u, p in attempts:
            print(f"    would try  {u}:{p or '<blank>'}")
        sys.exit("\n[*] Dry run complete - nothing sent.")

    found, partial = [], []
    with open(logfile, "w", encoding="utf-8") as log:
        log.write(f"# module={choice} target={url} started={datetime.now().isoformat()}\n")
        for i, (u, p) in enumerate(attempts, 1):
            kind, code, extra = module["auth"](session, url, u, p, timeout)
            log.write(f"{kind} {code} {u}:{p}\n")
            label = f"{u}:{p or '<blank>'}"

            if kind == "error":
                print(f"[!] Request error: {extra}")
                log.write(f"aborting: {extra}\n")
                break
            if kind == "backoff":
                print(f"[!] Rate-limit/lockout signal (HTTP {code}). Backing off {extra}s.")
                time.sleep(extra)
                continue
            if kind == "success":
                print(f"[+] SUCCESS  {label}  (HTTP {code})")
                found.append((u, p))
            elif kind == "partial":
                print(f"[~] VALID (no access)  {label}  (HTTP {code})")
                partial.append((u, p))
            else:
                print(f"[-] {code:>3}  {label}")

            if i < len(attempts):
                time.sleep(delay + random.uniform(0, delay / 2))

    print()
    if found:
        print("[+] Valid credentials with access:")
        for u, p in found:
            print(f"    {u}:{p or '<blank>'}")
    if partial:
        print("[~] Valid credentials, insufficient permission (worth noting):")
        for u, p in partial:
            print(f"    {u}:{p or '<blank>'}")
    if not found and not partial:
        print("[-] No valid default credentials found.")
    print(f"[*] Full log: {logfile}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted.")
