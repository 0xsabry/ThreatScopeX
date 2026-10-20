"""
ThreatScope V2 — Threat Intelligence Enrichment
Author: 0xSABRY

Async IOC enrichment via VirusTotal, AbuseIPDB, and AlienVault OTX APIs.
Rate-limited, cached lookups with inline results display.
"""

import json
import time
import base64
import logging
import hashlib
from pathlib import Path
from urllib.parse import quote
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from collections import defaultdict

logger = logging.getLogger("threatscope.intel")


def _url_segment(value: str) -> str:
    """Percent-encode a value so it cannot alter the request path/query."""
    return quote(str(value), safe="")


def _virustotal_url_id(url: str) -> str:
    """
    Compute the VirusTotal v3 URL identifier for a URL.

    VT uses the URL-safe base64 encoding of the URL (padding stripped), not a
    SHA-256 digest.
    """
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class EnrichmentCache:
    """Simple file-based cache for enrichment results."""

    def __init__(self, cache_dir: str = None, ttl_hours: int = 24):
        from config import DATA_DIR
        self.cache_dir = Path(cache_dir) if cache_dir else DATA_DIR / "enrichment_cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = ttl_hours * 3600

    def _key_path(self, key: str) -> Path:
        h = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{h}.json"

    def get(self, key: str) -> Optional[dict]:
        path = self._key_path(key)
        if path.exists():
            try:
                data = json.loads(path.read_text())
                if time.time() - data.get("_cached_at", 0) < self.ttl_seconds:
                    return data.get("result")
            except Exception:
                pass
        return None

    def set(self, key: str, result: dict):
        path = self._key_path(key)
        try:
            path.write_text(json.dumps({"_cached_at": time.time(), "result": result}))
        except Exception:
            pass


class ThreatIntelEnrichment:
    """
    Enriches IOCs (IPs, hashes, domains, URLs) by querying threat intelligence
    APIs: VirusTotal, AbuseIPDB, and AlienVault OTX.
    """

    def __init__(self, vt_key: str = "", abuseipdb_key: str = "", otx_key: str = ""):
        from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, OTX_API_KEY
        self.vt_key = vt_key or VIRUSTOTAL_API_KEY
        self.abuseipdb_key = abuseipdb_key or ABUSEIPDB_API_KEY
        self.otx_key = otx_key or OTX_API_KEY
        self.cache = EnrichmentCache()
        self.results: Dict[str, dict] = {}
        self._rate_limit_delay = 0.25

    def enrich_ioc(self, value: str, ioc_type: str) -> dict:
        """
        Enrich a single IOC by querying all available APIs.

        Args:
            value: The IOC value (IP, hash, domain, URL).
            ioc_type: Type of IOC.

        Returns:
            Enrichment results dictionary.
        """
        cache_key = f"{ioc_type}:{value}"
        cached = self.cache.get(cache_key)
        if cached:
            self.results[value] = cached
            return cached

        result = {
            "value": value,
            "type": ioc_type,
            "enrichment_time": datetime.now(timezone.utc).isoformat(),
            "sources": {},
            "verdict": "unknown",
            "risk_score": 0,
            "tags": [],
        }

        if not REQUESTS_AVAILABLE:
            result["error"] = "requests library not installed"
            return result

        # VirusTotal
        if self.vt_key:
            vt_result = self._query_virustotal(value, ioc_type)
            if vt_result:
                result["sources"]["virustotal"] = vt_result
                result["risk_score"] = max(result["risk_score"], vt_result.get("risk_score", 0))

        # AbuseIPDB (IPs only)
        if self.abuseipdb_key and ioc_type == "ipv4":
            abuse_result = self._query_abuseipdb(value)
            if abuse_result:
                result["sources"]["abuseipdb"] = abuse_result
                result["risk_score"] = max(result["risk_score"], abuse_result.get("risk_score", 0))

        # AlienVault OTX
        if self.otx_key:
            otx_result = self._query_otx(value, ioc_type)
            if otx_result:
                result["sources"]["otx"] = otx_result
                result["risk_score"] = max(result["risk_score"], otx_result.get("risk_score", 0))

        # Determine verdict
        if result["risk_score"] >= 75:
            result["verdict"] = "malicious"
        elif result["risk_score"] >= 40:
            result["verdict"] = "suspicious"
        elif result["risk_score"] > 0:
            result["verdict"] = "low_risk"
        else:
            result["verdict"] = "clean" if result["sources"] else "unknown"

        self.cache.set(cache_key, result)
        self.results[value] = result
        return result

    def enrich_all(self, iocs: Dict[str, set]) -> Dict[str, dict]:
        """
        Enrich all IOCs from an analysis session.

        Args:
            iocs: Dictionary of IOC type -> set of values.

        Returns:
            Dictionary of IOC value -> enrichment results.
        """
        enrichable_types = {"ipv4", "md5", "sha1", "sha256", "domain", "url"}
        total = sum(len(v) for k, v in iocs.items() if k in enrichable_types)

        if total == 0:
            return {}

        logger.info(f"Enriching {total} IOCs...")
        count = 0

        for ioc_type, values in iocs.items():
            if ioc_type not in enrichable_types:
                continue
            for value in list(values)[:50]:  # Limit per type
                try:
                    self.enrich_ioc(value, ioc_type)
                    count += 1
                    time.sleep(self._rate_limit_delay)
                except Exception as e:
                    logger.debug(f"Enrichment error for {value}: {e}")

        logger.info(f"Enriched {count}/{total} IOCs")
        return self.results

    def _query_virustotal(self, value: str, ioc_type: str) -> Optional[dict]:
        """Query VirusTotal API v3."""
        try:
            headers = {"x-apikey": self.vt_key}
            segment = _url_segment(value)
            type_map = {
                "ipv4": f"https://www.virustotal.com/api/v3/ip_addresses/{segment}",
                "domain": f"https://www.virustotal.com/api/v3/domains/{segment}",
                "md5": f"https://www.virustotal.com/api/v3/files/{segment}",
                "sha1": f"https://www.virustotal.com/api/v3/files/{segment}",
                "sha256": f"https://www.virustotal.com/api/v3/files/{segment}",
                "url": f"https://www.virustotal.com/api/v3/urls/{_virustotal_url_id(value)}",
            }
            url = type_map.get(ioc_type)
            if not url:
                return None

            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values()) if stats else 1

                return {
                    "malicious_detections": malicious,
                    "total_engines": total,
                    "detection_ratio": f"{malicious}/{total}",
                    "risk_score": int((malicious / max(total, 1)) * 100),
                    "reputation": data.get("reputation", 0),
                    "tags": data.get("tags", []),
                    "country": data.get("country", ""),
                    "as_owner": data.get("as_owner", ""),
                }
            elif resp.status_code == 404:
                return {"risk_score": 0, "status": "not_found"}
        except Exception as e:
            logger.debug(f"VT query error: {e}")
        return None

    def _query_abuseipdb(self, ip: str) -> Optional[dict]:
        """Query AbuseIPDB API."""
        try:
            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers, params=params, timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "risk_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "usage_type": data.get("usageType", ""),
                    "is_tor": data.get("isTor", False),
                    "is_public": data.get("isPublic", True),
                    "domain": data.get("domain", ""),
                }
        except Exception as e:
            logger.debug(f"AbuseIPDB query error: {e}")
        return None

    def _query_otx(self, value: str, ioc_type: str) -> Optional[dict]:
        """Query AlienVault OTX API."""
        try:
            headers = {"X-OTX-API-KEY": self.otx_key}
            segment = _url_segment(value)
            type_map = {
                "ipv4": f"https://otx.alienvault.com/api/v1/indicators/IPv4/{segment}/general",
                "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{segment}/general",
                "md5": f"https://otx.alienvault.com/api/v1/indicators/file/{segment}/general",
                "sha1": f"https://otx.alienvault.com/api/v1/indicators/file/{segment}/general",
                "sha256": f"https://otx.alienvault.com/api/v1/indicators/file/{segment}/general",
                "url": f"https://otx.alienvault.com/api/v1/indicators/url/{segment}/general",
            }
            url = type_map.get(ioc_type)
            if not url:
                return None

            resp = requests.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                return {
                    "pulse_count": pulse_count,
                    "risk_score": min(pulse_count * 10, 100),
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_code", ""),
                    "tags": data.get("pulse_info", {}).get("related", {}).get("alienvault", {}).get("tags", []),
                }
        except Exception as e:
            logger.debug(f"OTX query error: {e}")
        return None

    def get_summary(self) -> dict:
        """Get enrichment summary."""
        verdicts = defaultdict(int)
        for r in self.results.values():
            verdicts[r.get("verdict", "unknown")] += 1
        return {
            "total_enriched": len(self.results),
            "verdicts": dict(verdicts),
            "malicious_count": verdicts.get("malicious", 0),
            "suspicious_count": verdicts.get("suspicious", 0),
            "api_keys_configured": {
                "virustotal": bool(self.vt_key),
                "abuseipdb": bool(self.abuseipdb_key),
                "otx": bool(self.otx_key),
            },
        }
