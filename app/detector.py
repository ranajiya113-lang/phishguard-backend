"""
PhishingDetector — orchestrates all detection layers:
  1. URL heuristics (fast, no external calls)
  2. ML classifier (trained on phishing datasets)
  3. External threat intelligence (VirusTotal + Google Safe Browsing) — optional
"""

import asyncio
from urllib.parse import urlparse

from utils.heuristics import HeuristicsAnalyzer
from utils.ml_model import MLModel
from utils.threat_intel import ThreatIntelClient
from utils.url_utils import normalize_url, is_valid_url


class PhishingDetector:
    def __init__(self):
        self.heuristics = HeuristicsAnalyzer()
        self.ml_model = MLModel()
        self.threat_intel = ThreatIntelClient()

    async def analyze(self, url: str, vt_api_key: str = None, google_api_key: str = None) -> dict:
        # Normalize + validate
        url = normalize_url(url)
        if not is_valid_url(url):
            return self._build_response(url, 0.95, {"error": "Invalid or malformed URL"})

        # --- Layer 1: Heuristics (synchronous, very fast) ---
        heuristic_result = self.heuristics.analyze(url)

        # --- Layer 2: ML model ---
        ml_result = self.ml_model.predict(url)

        # --- Layer 3: External threat intel (async, only if API keys provided or free tier) ---
        intel_result = await self.threat_intel.check(url, vt_api_key=vt_api_key, google_api_key=google_api_key)

        # --- Weighted ensemble score ---
        score = self._compute_ensemble_score(heuristic_result, ml_result, intel_result)

        details = {
            "heuristics": heuristic_result,
            "ml_model": ml_result,
            "threat_intel": intel_result,
        }

        return self._build_response(url, score, details)

    def _compute_ensemble_score(self, heuristic: dict, ml: dict, intel: dict) -> float:
        """
        Weighted ensemble:
          - Heuristics: 30%
          - ML model:   40%
          - Threat intel: 30% (if available, else redistribute)
        """
        h_score = heuristic.get("score", 0.0)
        m_score = ml.get("score", 0.0)
        i_score = intel.get("score", None)

        if i_score is not None:
            # Hard override: if ANY external intel flags it, boost score significantly
            if intel.get("flagged_by_virustotal") or intel.get("flagged_by_google"):
                return min(1.0, 0.3 * h_score + 0.4 * m_score + 0.3 * i_score + 0.25)
            return 0.30 * h_score + 0.40 * m_score + 0.30 * i_score
        else:
            # No external intel — redistribute weights
            return 0.40 * h_score + 0.60 * m_score

    def _build_response(self, url: str, score: float, details: dict) -> dict:
        score = round(min(max(score, 0.0), 1.0), 4)

        if score >= 0.70:
            risk_level = "dangerous"
            is_phishing = True
        elif score >= 0.40:
            risk_level = "suspicious"
            is_phishing = False  # warn but don't hard-block
        else:
            risk_level = "safe"
            is_phishing = False

        # Confidence is higher when multiple signals agree
        h = details.get("heuristics", {}).get("score", 0)
        m = details.get("ml_model", {}).get("score", 0)
        agreement = 1.0 - abs(h - m)
        confidence = round(0.5 + 0.5 * agreement, 4)

        return {
            "url": url,
            "is_phishing": is_phishing,
            "risk_score": score,
            "risk_level": risk_level,
            "confidence": confidence,
            "details": details,
        }
