"""
PhishGuard Pro - optional "deep scan"
=====================================
Unlike the rest of the program, this DOES contact the website (DNS lookup,
TLS certificate, and following redirects with headers only - no page body is
downloaded or executed).  It is always opt-in.

Standard library only.
"""

import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import urljoin, urlparse

import engine

REDIRECT_CODES = (301, 302, 303, 307, 308)


def deep_scan(url: str, timeout: float = 4.0) -> dict:
    """
    Returns {"findings": [(points, reason)], "notes": [str], "ip": str|None,
             "final_url": str|None, "cert_age_days": int|None}
    Never raises for network problems - they become notes.
    """
    out = {"findings": [], "notes": [], "ip": None, "final_url": None, "cert_age_days": None}
    p = engine.parse_url(url)

    # ---- DNS ---------------------------------------------------------
    try:
        ip = socket.gethostbyname(p.host)
    except OSError:
        out["findings"].append((10, "Domain does not resolve in DNS (taken down, fake, or mistyped)."))
        out["notes"].append("DNS lookup failed; skipped SSL and redirect checks.")
        return out
    out["ip"] = ip
    try:
        if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
            out["notes"].append(f"{p.host} points to a private/local address ({ip}); network checks skipped.")
            return out
    except ValueError:
        pass

    # ---- TLS certificate --------------------------------------------
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((p.host, 443), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=p.host) as tls:
                cert = tls.getpeercert()
        issued = ssl.cert_time_to_seconds(cert["notBefore"])
        age = int((time.time() - issued) / 86400)
        out["cert_age_days"] = age
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        out["notes"].append(f"Valid certificate from {issuer.get('organizationName', 'unknown issuer')}, issued {age} day(s) ago.")
        if age < 14:
            out["findings"].append((15, f"SSL certificate was issued only {age} day(s) ago (new sites are riskier)."))
        elif age < 45:
            out["findings"].append((6, f"SSL certificate is fairly new ({age} days old)."))
    except ssl.SSLCertVerificationError as e:
        out["findings"].append((25, f"SSL certificate is invalid: {e.verify_message}."))
    except (OSError, ssl.SSLError):
        out["notes"].append("No working HTTPS service found on port 443.")

    # ---- Redirect chain (headers only) -------------------------------
    current = p.raw if "://" in p.raw else "http://" + p.raw
    first_reg = p.reg
    hops = 0
    try:
        for _ in range(6):
            u = urlparse(current)
            Conn = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
            conn = Conn(u.hostname, u.port, timeout=timeout)
            try:
                conn.request("GET", (u.path or "/") + (("?" + u.query) if u.query else ""),
                             headers={"User-Agent": "PhishGuardPro/1.0", "Accept": "text/html"})
                resp = conn.getresponse()
                status, loc = resp.status, resp.getheader("Location")
            finally:
                conn.close()
            if status in REDIRECT_CODES and loc:
                current = urljoin(current, loc)
                hops += 1
                continue
            break
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        out["notes"].append("Could not follow redirects (connection problem).")
    out["final_url"] = current
    if hops:
        final_reg = engine.registered_domain((urlparse(current).hostname or "").lower())
        out["notes"].append(f"Followed {hops} redirect(s) to {current}")
        if final_reg and final_reg != first_reg:
            out["findings"].append((10, f"Redirects to a different domain ({final_reg})."))
        if hops >= 3:
            out["findings"].append((8, f"Long redirect chain ({hops} hops)."))
    return out
