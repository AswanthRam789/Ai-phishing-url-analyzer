import re
from datetime import datetime, timezone
import tldextract
import whois


class FeatureExtractor:
    def __init__(self, url: str):
        # Ensure URL has a scheme so parsing behaves consistently
        self.raw_url = url.strip()
        self.url = self.raw_url if self.raw_url.startswith(("http://", "https://")) else f"http://{self.raw_url}"
        self.ext = tldextract.extract(self.url)

    def extract_lexical_features(self) -> dict:
        """Extracts structural URL indicators used in phishing detection."""
        # Check for IPv4 address in the URL
        is_ip = bool(re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', self.url))
        
        # Count subdomains (e.g., 'a.b.example.com' -> 2 subdomains)
        subdomains = [s for s in self.ext.subdomain.split('.') if s] if self.ext.subdomain else []
        
        # Construct registered domain (e.g., 'google.com')
        registered_domain = f"{self.ext.domain}.{self.ext.suffix}" if self.ext.suffix else self.ext.domain

        return {
            "normalized_url": self.url,
            "registered_domain": registered_domain,
            "subdomain": self.ext.subdomain,
            "url_length": len(self.url),
            "dot_count": self.url.count('.'),
            "hyphen_count": self.url.count('-'),
            "has_at_symbol": "@" in self.url,
            "uses_https": self.url.startswith("https://"),
            "is_ip_address": is_ip,
            "subdomain_count": len(subdomains)
        }

    def get_whois_info(self) -> dict:
        """Queries WHOIS records to determine domain age and registrar."""
        registered_domain = f"{self.ext.domain}.{self.ext.suffix}" if self.ext.suffix else ""
        
        if not registered_domain or re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', registered_domain):
            return {"domain_age_days": None, "registrar": "N/A (IP or Invalid Domain)"}

        try:
            w = whois.whois(registered_domain)
            creation_date = w.creation_date

            # Some WHOIS servers return a list of dates; take the earliest one
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            age_days = None
            if isinstance(creation_date, datetime):
                # Normalize timezone awareness before subtracting
                if creation_date.tzinfo is not None:
                    now = datetime.now(timezone.utc)
                else:
                    now = datetime.now()
                age_days = (now - creation_date).days

            registrar = w.registrar[0] if isinstance(w.registrar, list) else w.registrar

            return {
                "domain_age_days": age_days,
                "registrar": registrar or "Unknown"
            }
        except Exception:
            return {
                "domain_age_days": None,
                "registrar": "WHOIS Lookup Failed / Privacy Protected"
            }


# Quick standalone test block
if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.50/secure-login@paypal-verify.com/update"
    ]
    for u in test_urls:
        print(f"\n--- Testing: {u} ---")
        fe = FeatureExtractor(u)
        print("Lexical:", fe.extract_lexical_features())
        print("WHOIS:", fe.get_whois_info())