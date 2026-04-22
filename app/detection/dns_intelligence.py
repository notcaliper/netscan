from __future__ import annotations

import logging
import socket
import yaml
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

from app.db.db_session import SessionLocal
from app.db.models import DNSAnalysis

logger = logging.getLogger("netscan.dns_intel")

class DNSIntelligenceModule:
    """
    Module to analyze DNS queries for restricted activities.
    - Classifies domains (gambling, piracy, vpn, normal)
    - Resolves domains to IPs
    - Persists results to the database
    """

    def __init__(self, config_path: str = "config/dns_intelligence.yaml"):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.intel = self.config.get("intelligence", {})
        self.resolvers = self.config.get("resolvers", ["1.1.1.1", "8.8.8.8"])
        self.cached_feeds = {}
        self._load_threat_feeds()

    def _load_threat_feeds(self):
        """Download or load cached threat intelligence feeds."""
        feeds = self.config.get("feeds", {})
        cache_dir = Path("config/cache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        for category, url in feeds.items():
            if not url:
                continue
            
            cache_file = cache_dir / f"{category}_feed.txt"
            domain_set = set()
            
            # Check if cache is older than 24 hours
            needs_download = True
            if cache_file.exists():
                file_age = time.time() - cache_file.stat().st_mtime
                if file_age < 86400: # 24 hours
                    needs_download = False
            
            if needs_download:
                try:
                    logger.info("Downloading Threat Feed for %s...", category)
                    req = urllib.request.Request(url, headers={'User-Agent': 'NetScan-NIDS/1.0'})
                    with urllib.request.urlopen(req, timeout=10) as response:
                        content = response.read().decode('utf-8')
                        
                    # Save to cache
                    with open(cache_file, "w") as f:
                        f.write(content)
                    logger.info("Successfully downloaded %s feed.", category)
                except Exception as e:
                    logger.error("Failed to download feed %s from %s: %s", category, url, e)
            
            # Load from cache
            if cache_file.exists():
                try:
                    with open(cache_file, "r") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#"):
                                parts = line.split()
                                if len(parts) >= 2:
                                    domain_set.add(parts[1].lower())
                                elif len(parts) == 1:
                                    domain_set.add(parts[0].lower())
                    self.cached_feeds[category] = domain_set
                    logger.info("Loaded %d domains for %s feed.", len(domain_set), category)
                except Exception as e:
                    logger.error("Failed to read cache file %s: %s", cache_file, e)

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            logger.warning("DNS Intelligence config not found at %s. Using defaults.", self.config_path)
            return {}
        try:
            with open(self.config_path, "r") as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error("Failed to load DNS Intelligence config: %s", e)
            return {}

    def resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve a domain to an IP address using system resolver."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None
        except Exception as e:
            logger.debug("DNS resolution failed for %s: %s", domain, e)
            return None

    def classify_domain(self, domain: str) -> Dict[str, Any]:
        """Classify a domain based on keywords and known lists."""
        domain_lower = domain.lower()
        
        # 1. Check Whitelist explicitly to avoid false positives (e.g. googlezip.net)
        whitelist = self.config.get("whitelist", [])
        for wl_domain in whitelist:
            if wl_domain.lower() in domain_lower:
                return {
                    "category": "normal",
                    "risk_score": 0.0,
                    "reason": f"Domain matched whitelist: {wl_domain}"
                }
        
        # 2. Check Global Threat Intelligence Feeds (Fast O(1) set lookup)
        for feed_category, domain_set in self.cached_feeds.items():
            if domain_lower in domain_set:
                return {
                    "category": feed_category,
                    "risk_score": 0.85, # Feeds get high confidence score
                    "reason": f"Domain matched global Threat Intel Feed: {feed_category}"
                }
        
        # 3. Check Manual Config YAML Rules
        for category, data in self.intel.items():
            # Check direct domain match
            if domain_lower in [d.lower() for d in data.get("domains", [])]:
                return {
                    "category": category,
                    "risk_score": data.get("risk_score", 0.5),
                    "reason": f"Domain matched {category} intel list"
                }
            
            # Check keyword match
            for keyword in data.get("keywords", []):
                if keyword.lower() in domain_lower:
                    return {
                        "category": category,
                        "risk_score": data.get("risk_score", 0.5),
                        "reason": f"Domain matched restricted keyword: {keyword}"
                    }
        
        return {
            "category": "normal",
            "risk_score": 0.0,
            "reason": "No restricted patterns found"
        }

    def get_ip_intel(self, ip: str) -> Dict[str, Any]:
        """Fetch ASN and Org data from IPinfo."""
        token = self.config.get("ipinfo", {}).get("token")
        if not token or not ip:
            return {}
        
        try:
            import requests # Using requests as it's in requirements.txt
            url = f"https://ipinfo.io/{ip}/json?token={token}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    "asn": data.get("org", ""), # IPinfo usually puts ASN in 'org' field like "AS15169 Google LLC"
                    "org": data.get("org", ""),
                    "country": data.get("country", "")
                }
        except Exception as e:
            logger.debug("IPinfo lookup failed for %s: %s", ip, e)
        return {}

    def analyze_query(self, src_ip: str, domain: str) -> Dict[str, Any]:
        """
        Perform full DNS intelligence analysis.
        - Resolve IP
        - Classification
        - IP intelligence (ASN/Org)
        - Return structured result
        """
        resolved_ip = self.resolve_domain(domain)
        classification = self.classify_domain(domain)
        ip_intel = self.get_ip_intel(resolved_ip) if resolved_ip else {}
        
        # If normal by domain, check if ASN/Org reveals anything (e.g., VPN providers)
        reason = classification["reason"]
        category = classification["category"]
        risk_score = classification["risk_score"]
        
        if category == "normal" and ip_intel.get("org"):
            org_lower = ip_intel["org"].lower()
            # Basic check for known VPN/Hosting as indicators
            vpn_providers = ["mullvad", "nordvpn", "expressvpn", "surfshark", "packet-hub"]
            for vpn in vpn_providers:
                if vpn in org_lower:
                    category = "vpn"
                    risk_score = 0.55
                    reason = f"IP ASN/Org matched VPN provider: {ip_intel['org']}"
                    break

        result = {
            "src_ip": src_ip,
            "domain": domain,
            "resolved_ip": resolved_ip,
            "category": category,
            "risk_score": risk_score,
            "reason": f"{reason} | ASN: {ip_intel.get('asn', 'unknown')}" if ip_intel.get("asn") else reason
        }
        
        # Persist to DB
        self._persist_result(result)
        
        return result

    def _persist_result(self, result: Dict[str, Any]) -> None:
        """Save analysis result to the database."""
        session = SessionLocal()
        try:
            analysis = DNSAnalysis(
                src_ip=result["src_ip"],
                domain=result["domain"],
                resolved_ip=result["resolved_ip"],
                category=result["category"],
                risk_score=result["risk_score"],
                reason=result["reason"]
            )
            session.add(analysis)
            session.commit()
        except Exception as e:
            session.rollback()
            logger.error("Failed to persist DNS analysis result: %s", e)
        finally:
            session.close()

if __name__ == "__main__":
    # Quick test
    logging.basicConfig(level=logging.INFO)
    intel = DNSIntelligenceModule()
    print(intel.analyze_query("10.0.0.1", "example-casino.com"))
    print(intel.analyze_query("10.0.0.1", "google.com"))
