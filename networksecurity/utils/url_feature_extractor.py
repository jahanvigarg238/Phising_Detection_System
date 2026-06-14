"""
URL Feature Extractor
Converts a raw URL into the 30 features expected by the phishing detection model.
All features return -1 (phishing indicator), 0 (suspicious), or 1 (legitimate).
"""

import re
import socket
import urllib.request
from urllib.parse import urlparse
import ipaddress


def _safe_domain(netloc: str) -> str:
    return netloc.lower().replace("www.", "")


def _host_from_domain(domain: str) -> str:
    return domain.split(":")[0]


def _compute_having_ip_address(domain: str) -> int:
    try:
        ipaddress.ip_address(_host_from_domain(domain))
        return -1
    except ValueError:
        return 1


def _compute_url_length(url: str) -> int:
    length = len(url)
    if length < 54:
        return 1
    if length <= 75:
        return 0
    return -1


def _compute_shortining_service(domain: str) -> int:
    shorteners = [
        "bit.ly", "goo.gl", "tinyurl", "ow.ly", "t.co", "is.gd",
        "buff.ly", "short.link", "rb.gy", "cutt.ly", "tiny.cc"
    ]
    return -1 if any(s in domain for s in shorteners) else 1


def _compute_having_sub_domain(domain: str) -> int:
    dots = domain.count(".")
    if dots == 1:
        return 1
    if dots == 2:
        return 0
    return -1


def _compute_domain_registration_length(domain: str) -> int:
    suspicious_tlds = [
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
        ".click", ".loan", ".win", ".bid", ".racing", ".stream"
    ]
    return -1 if any(domain.endswith(t) for t in suspicious_tlds) else 1


def _compute_port(parsed) -> int:
    port = parsed.port
    return 1 if port is None or port in [80, 443] else -1


def _compute_abnormal_url(domain: str) -> int:
    try:
        socket.gethostbyname(_host_from_domain(domain))
        return 1
    except Exception:
        return -1


def _compute_redirect(full_url: str) -> int:
    redirects = full_url.count("//") - 1
    return 0 if redirects <= 1 else -1


def _compute_age_of_domain(domain: str) -> int:
    trusted_tlds = [".com", ".org", ".edu", ".gov", ".net", ".co.uk", ".ac.in"]
    return 1 if any(domain.endswith(t) for t in trusted_tlds) else -1


def _compute_dns_record(domain: str) -> int:
    try:
        socket.gethostbyname(_host_from_domain(domain))
        return 1
    except Exception:
        return -1


def _compute_web_traffic(domain: str) -> int:
    known_domains = [
        "google", "youtube", "facebook", "twitter", "instagram",
        "linkedin", "microsoft", "apple", "amazon", "github",
        "wikipedia", "reddit", "paypal", "netflix", "spotify"
    ]
    return 1 if any(k in domain for k in known_domains) else -1


def _compute_links_pointing_to_page(features: dict) -> int:
    if features["web_traffic"] == 1:
        return 1
    if features["having_IP_Address"] == -1:
        return -1
    return 0


def _compute_statistical_report(full_url: str, sslfinal_state: int) -> int:
    phishing_keywords = [
        "secure", "account", "update", "login", "signin",
        "verify", "banking", "confirm", "password", "credential"
    ]
    phish_score = sum(1 for kw in phishing_keywords if kw in full_url)
    if phish_score >= 2:
        return -1
    if phish_score == 1 and sslfinal_state == -1:
        return -1
    return 1


def _normalize_url(url: str) -> str:
    if url.startswith(("http://", "https://")):
        return url
    return "http://" + url


def _has_at_symbol(url: str) -> int:
    return -1 if "@" in url else 1


def _double_slash_redirecting(full_url: str) -> int:
    return -1 if full_url.rfind("//") > 7 else 1


def _prefix_suffix(domain: str) -> int:
    return -1 if "-" in domain else 1


def _favicon(scheme: str) -> int:
    return 1 if scheme == "https" else -1


def _links_in_tags(scheme: str) -> int:
    return 1 if scheme == "https" else -1


def _request_url(path: str) -> int:
    return -1 if len(re.findall(r'https?://', path)) > 0 else 1


def _url_of_anchor(url: str) -> int:
    return -1 if "#" in url and len(url.split("#")[1]) > 10 else 1


def _sfh(full_url: str) -> int:
    return -1 if "about:blank" in full_url or "javascript:" in full_url else 1


def _submitting_to_email(full_url: str) -> int:
    return -1 if "mailto:" in full_url else 1


def _on_mouseover(full_url: str) -> int:
    return -1 if "onmouseover" in full_url else 1


def _rightclick(full_url: str) -> int:
    return -1 if "contextmenu" in full_url or "rightclick" in full_url else 1


def _popupwindow(full_url: str) -> int:
    return -1 if "popup" in full_url or "alert(" in full_url else 1


def _iframe(full_url: str) -> int:
    return -1 if "iframe" in full_url else 1


def _build_primary_features(url: str, parsed, domain: str, path: str, full_url: str) -> dict:
    return {
        "having_IP_Address": _compute_having_ip_address(domain),
        "URL_Length": _compute_url_length(url),
        "Shortining_Service": _compute_shortining_service(domain),
        "having_At_Symbol": _has_at_symbol(url),
        "double_slash_redirecting": _double_slash_redirecting(full_url),
        "Prefix_Suffix": _prefix_suffix(domain),
        "having_Sub_Domain": _compute_having_sub_domain(domain),
        "SSLfinal_State": 1 if parsed.scheme == "https" else -1,
        "Domain_registeration_length": _compute_domain_registration_length(domain),
        "Favicon": _favicon(parsed.scheme),
        "port": _compute_port(parsed),
        "HTTPS_token": -1 if "https" in domain else 1,
        "Request_URL": _request_url(path),
        "URL_of_Anchor": _url_of_anchor(url),
        "Links_in_tags": _links_in_tags(parsed.scheme),
        "SFH": _sfh(full_url),
        "Submitting_to_email": _submitting_to_email(full_url),
        "Abnormal_URL": _compute_abnormal_url(domain),
        "Redirect": _compute_redirect(full_url),
        "on_mouseover": _on_mouseover(full_url),
        "RightClick": _rightclick(full_url),
        "popUpWidnow": _popupwindow(full_url),
        "Iframe": _iframe(full_url),
        "age_of_domain": _compute_age_of_domain(domain),
        "DNSRecord": _compute_dns_record(domain),
        "web_traffic": _compute_web_traffic(domain),
    }


def _add_secondary_features(features: dict, parsed, full_url: str) -> None:
    features["Page_Rank"] = 1 if features["DNSRecord"] == 1 and parsed.scheme == "https" else -1
    features["Google_Index"] = 1 if features["DNSRecord"] == 1 else -1
    features["Links_pointing_to_page"] = _compute_links_pointing_to_page(features)
    features["Statistical_report"] = _compute_statistical_report(full_url, features["SSLfinal_State"])


def extract_features(url: str) -> dict:
    """Extract all 30 phishing detection features from a URL."""

    url = _normalize_url(url)
    parsed = urlparse(url)
    domain = _safe_domain(parsed.netloc)
    path = parsed.path
    full_url = url.lower()

    features = _build_primary_features(url, parsed, domain, path, full_url)
    _add_secondary_features(features, parsed, full_url)

    return features


def features_to_dataframe(features: dict):
    """Convert feature dict to pandas DataFrame for model input."""
    import pandas as pd
    return pd.DataFrame([features])
