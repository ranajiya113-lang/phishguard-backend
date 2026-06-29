"""
External threat intelligence:
  - VirusTotal API v3 (free tier: 4 requests/min, 500/day)
  - Google Safe Browsing API v4 (free tier: 10,000 req/day)
Both are optional; if no API key is provided, we skip gracefully.
"""

import asyncio
import hashlib
import base64
import httpx
import os

# Can also set these via environment variables
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GOOGLE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")


class ThreatIntelClient:

    async def check(self, url: str, vt_api_key: str = None, google_api_key: str = None) -> dict:
        vt_key = vt_api_key or VT_API_KEY
        g_key = google_api_key or GOOGLE_API_KEY

        results = await asyncio.gather(
            self._check_virustotal(url, vt_key) if vt_key else asyncio.sleep(0),
            self._check_google_safe_browsing(url, g_key) if g_key else asyncio.sleep(0),
        )

        vt_result = results[0] if vt_key else None
        gsb_result = results[1] if g_key else None

        if vt_result is None and gsb_result is None:
            return {
                "score": None,
                "available": False,
                "message": "No threat intel API keys provided. Set VIRUSTOTAL_API_KEY and/or GOOGLE_SAFE_BROWSING_API_KEY env vars for higher accuracy.",
            }

        flagged_vt = vt_result.get("flagged", False) if isinstance(vt_result, dict) else False
        flagged_gsb = gsb_result.get("flagged", False) if isinstance(gsb_result, dict) else False

        # Score: 1.0 if flagged by either, 0.0 if both clean
        if flagged_vt or flagged_gsb:
            score = 1.0
        else:
            score = 0.0

        return {
            "score": score,
            "available": True,
            "flagged_by_virustotal": flagged_vt,
            "flagged_by_google": flagged_gsb,
            "virustotal": vt_result,
            "google_safe_browsing": gsb_result,
        }

    async def _check_virustotal(self, url: str, api_key: str) -> dict:
        """
        VirusTotal v3 — URL analysis.
        Encodes URL as base64 ID, checks existing analysis first (no quota used),
        then submits for scan if not found.
        """
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            headers = {"x-apikey": api_key}

            async with httpx.AsyncClient(timeout=10) as client:
                # Check if already analyzed
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/urls/{url_id}",
                    headers=headers
                )

                if resp.status_code == 404:
                    # Submit for analysis
                    submit = await client.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=headers,
                        data={"url": url}
                    )
                    if submit.status_code != 200:
                        return {"flagged": False, "error": "Submission failed"}
                    analysis_id = submit.json()["data"]["id"]

                    # Poll for result (max 3 tries)
                    for _ in range(3):
                        await asyncio.sleep(2)
                        poll = await client.get(
                            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers=headers
                        )
                        if poll.json().get("data", {}).get("attributes", {}).get("status") == "completed":
                            resp = poll
                            break

                if resp.status_code != 200:
                    return {"flagged": False, "error": f"VT API error: {resp.status_code}"}

                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1

                flagged = (malicious + suspicious) >= 2

                return {
                    "flagged": flagged,
                    "malicious_engines": malicious,
                    "suspicious_engines": suspicious,
                    "total_engines": total,
                    "detection_ratio": f"{malicious}/{total}",
                }

        except httpx.TimeoutException:
            return {"flagged": False, "error": "VirusTotal request timed out"}
        except Exception as e:
            return {"flagged": False, "error": str(e)}

    async def _check_google_safe_browsing(self, url: str, api_key: str) -> dict:
        """
        Google Safe Browsing API v4 — checks against Google's threat databases.
        """
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                    json=payload,
                )
                if resp.status_code != 200:
                    return {"flagged": False, "error": f"GSB API error: {resp.status_code}"}

                data = resp.json()
                matches = data.get("matches", [])
                flagged = len(matches) > 0
                threat_types = list({m.get("threatType") for m in matches})

                return {
                    "flagged": flagged,
                    "threat_types": threat_types,
                    "match_count": len(matches),
                }
        except httpx.TimeoutException:
            return {"flagged": False, "error": "Google Safe Browsing request timed out"}
        except Exception as e:
            return {"flagged": False, "error": str(e)}
