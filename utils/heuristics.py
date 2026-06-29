"""
Rule-based heuristics for phishing detection.
Fast, zero-dependency, explainable signals.
"""

import re
from urllib.parse import urlparse
from utils.url_utils import extract_features


# Known legitimate domains (allowlist for brand impersonation checks)
LEGITIMATE_BRANDS = {
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "netflix": "netflix.com",
    "bank": None,  # generic — no single domain
    "wellsfargo": "wellsfargo.com",
    "chase": "chase.com",
    "citibank": "citibank.com",
    "hsbc": "hsbc.com",
}

SUSPICIOUS_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "loan", "online", "site", "link"}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly"}


class HeuristicsAnalyzer:

    def analyze(self, url: str) -> dict:
        features = extract_features(url)
        parsed = urlparse(url)
        domain = parsed.netloc.lower().lstrip("www.")

        flags = []
        score = 0.0

        # --- Rule 1: IP address as host (+0.4) ---
        if features["has_ip_address"]:
            flags.append("IP address used as hostname (high risk)")
            score += 0.40

        # --- Rule 2: Very long URL (+0.15–0.25) ---
        if features["url_length"] > 100:
            flags.append(f"Unusually long URL ({features['url_length']} chars)")
            score += 0.20
        elif features["url_length"] > 75:
            score += 0.10

        # --- Rule 3: Too many subdomains (+0.2) ---
        if features["num_subdomains"] >= 3:
            flags.append(f"Excessive subdomains ({features['num_subdomains']})")
            score += 0.20

        # --- Rule 4: No HTTPS (+0.1) ---
        if not features["has_https"]:
            flags.append("No HTTPS (unencrypted)")
            score += 0.10

        # --- Rule 5: Suspicious TLD (+0.25) ---
        if features["is_risky_tld"]:
            flags.append(f"Risky TLD: .{features['tld']}")
            score += 0.25

        # --- Rule 6: @ sign in URL (+0.35) ---
        if features["num_at_signs"] > 0:
            flags.append("@ symbol in URL (browser ignores everything before @)")
            score += 0.35

        # --- Rule 7: Brand impersonation ---
        brand_flag = self._check_brand_impersonation(domain, url.lower())
        if brand_flag:
            flags.append(brand_flag)
            score += 0.40

        # --- Rule 8: URL shortener (+0.15) ---
        if features["is_shortened"]:
            flags.append("URL shortener detected (hides real destination)")
            score += 0.15

        # --- Rule 9: Hex / URL encoding tricks (+0.2) ---
        if features["has_hex_encoding"] and features["url_length"] > 50:
            flags.append("Suspicious URL encoding in long URL")
            score += 0.20

        # --- Rule 10: Double slash in path (+0.15) ---
        if features["has_double_slash"]:
            flags.append("Double slash in URL path")
            score += 0.15

        # --- Rule 11: Too many hyphens in domain (+0.15) ---
        domain_part = domain.split("/")[0]
        hyphen_count = domain_part.count("-")
        if hyphen_count >= 3:
            flags.append(f"Many hyphens in domain ({hyphen_count})")
            score += 0.20
        elif hyphen_count == 2:
            score += 0.10

        # --- Rule 12: Digits in domain (+0.10) ---
        if features["num_digits_in_domain"] >= 3:
            flags.append("Many digits in domain name")
            score += 0.10

        # --- Rule 13: Sensitive keywords in URL ---
        sensitive_keywords = ["update-account", "verify-account", "confirm-email",
                               "reset-password", "suspended", "unlock", "unusual-activity"]
        for kw in sensitive_keywords:
            if kw in url.lower():
                flags.append(f"Suspicious keyword: '{kw}'")
                score += 0.15
                break

        # --- Rule 14: Port in URL (non-standard) ---
        if parsed.port and parsed.port not in (80, 443, 8080, 8443):
            flags.append(f"Non-standard port: {parsed.port}")
            score += 0.15

        score = round(min(score, 1.0), 4)

        return {
            "score": score,
            "flags": flags,
            "flags_count": len(flags),
            "features": features,
        }

    def _check_brand_impersonation(self, domain: str, full_url: str) -> str | None:
        """
        Detect brand name in URL but domain is NOT the real brand domain.
        e.g. paypal-secure-login.com → paypal in domain but not paypal.com
        """
        for brand, real_domain in LEGITIMATE_BRANDS.items():
            if brand in domain or brand in full_url:
                if real_domain and not domain.endswith(real_domain):
                    return f"Brand impersonation: '{brand}' mentioned but domain is not {real_domain}"
        return None
