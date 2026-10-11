import json
import re
from datetime import datetime
import requests

class BallisticShieldDetector:

    def __init__(self, target_url: str, fraud_db: dict, timeout: int = 10):
        """
        Initializes the scanner.
        :param target_url: The target URL to investigate.
        :param fraud_db: External database of fraud signatures (IoC - Indicators of Compromise).
        """
        self.target_url = target_url.strip().rstrip("/")
        self.timeout = timeout
        self.fraud_db = fraud_db  # Injecting dynamic database into the scanner
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        }
        
        self.findings = {
            "target_url": self.target_url,
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "shop_ids": [],
            "tracking_signatures": {},
            "catalog_analysis": {},
            "identity_anomalies": {},
            "risk_score": 0,
            "critical_flags": []
        }

    def fetch_url(self, path: str = "") -> tuple[int, str]:
        url = f"{self.target_url}{path}"
        try:
            response = requests.get(url, headers=self.headers, timeout=self.timeout)
            return response.status_code, response.text
        except requests.RequestException as e:
            return 0, str(e)

    def analyze_catalog_speed(self):
        """Analyzes product deployment timestamps and vendor variable leaks."""
        status_code, content = self.fetch_url("/products.json?limit=250")
        if status_code != 200:
            return

        try:
            data = json.loads(content)
            products = data.get("products", [])
            if not products:
                return

            timestamps = []
            vendors = set()

            for p in products:
                if p.get("created_at"): timestamps.append(p.get("created_at"))
                if p.get("vendor"): vendors.add(p.get("vendor").upper())

            # Heuristic: Automated deployment detection (Superhuman Speed)
            if len(timestamps) > 1:
                timestamp_counts = {t: timestamps.count(t) for t in set(timestamps)}
                max_same_second = max(timestamp_counts.values())
                if max_same_second >= 10:  # >= 10 products injected in 1 second
                    self.findings["risk_score"] += 35
                    self.findings["critical_flags"].append("SUPERHUMAN_SPEED_DEPLOYMENT")

            # Cross-reference leaked vendors with the dynamic database
            known_vendors = [v.upper() for v in self.fraud_db.get("known_vendor_names", [])]
            for v in vendors:
                if v in known_vendors:
                    self.findings["risk_score"] += 40
                    self.findings["critical_flags"].append(f"KNOWN_FRAUD_VENDOR_{v}")

        except json.JSONDecodeError:
            pass

    def analyze_source_code(self):
        """Parses the DOM and cross-references with the dynamic IoC signature database."""
        status_code, html = self.fetch_url("/")
        if status_code != 200:
            return

        # 1. Extract SaaS Shop ID and cross-reference with the database
        shop_id_patterns = [
            r'Shopify\.shop\s*=\s*["\']([^"\']+)["\']',
            r'"shopId":\s*(\d+)',
            r'myshopify\.com\/(\d+)'
        ]
        found_shop_ids = set()
        for pattern in shop_id_patterns:
            found_shop_ids.update(re.findall(pattern, html))

        if found_shop_ids:
            self.findings["shop_ids"] = list(found_shop_ids)
            known_shop_ids = set(self.fraud_db.get("known_shop_ids", []))
            
            if found_shop_ids.intersection(known_shop_ids):
                self.findings["risk_score"] += 50
                self.findings["critical_flags"].append("MATCH_KNOWN_CRIMINAL_SHOP_ID")

        # 2. Check dynamic tracking identifiers
        clarity_match = re.search(r'clarity\.ms\/tag\/([a-zA-Z0-9]+)', html)
        if clarity_match:
            clarity_id = clarity_match.group(1)
            self.findings["tracking_signatures"]["microsoft_clarity"] = clarity_id
            
            # Cross-reference with our blacklist
            if clarity_id in self.fraud_db.get("known_clarity_ids", []):
                self.findings["risk_score"] += 45
                self.findings["critical_flags"].append("MATCH_BLACKLISTED_TRACKER_ID")

        # 3. Dynamic scanning for text anomalies / fake identities
        # The algorithm iterates through a list of stolen registry numbers provided by the bank
        for registry_id in self.fraud_db.get("stolen_registry_numbers", []):
            if registry_id in html:
                self.findings["risk_score"] += 40
                self.findings["critical_flags"].append(f"STOLEN_IDENTITY_DETECTED:_{registry_id}")

        # The algorithm iterates through specific code errors (e.g., pasted session codes instead of TAX IDs)
        for anomaly_string in self.fraud_db.get("corrupted_identity_strings", []):
            if anomaly_string in html:
                self.findings["risk_score"] += 40
                self.findings["critical_flags"].append(f"KNOWN_CODE_ANOMALY_DETECTED")

    def run_full_scan(self) -> dict:
        self.analyze_source_code()
        self.analyze_catalog_speed()
        self.findings["risk_score"] = min(self.findings["risk_score"], 100)
        return self.findings


# ==========================================
# DEPLOYMENT / USAGE EXAMPLE FOR A BANK
# ==========================================
if __name__ == "__main__":
    
    # 1. LOAD THE DATABASE (In production, fetched via API or a JSON file)
    # Here, the system administrator (e.g., SOC analyst) defines what to look for
    FRAUD_DATABASE = {
        "known_shop_ids": [
            "Enter_Compromised_Shop_ID_1", 
            "Enter_Compromised_Shop_ID_2"
        ],
        "known_clarity_ids": [
            "Enter_Blacklisted_Clarity_Project_1"
        ],
        "known_vendor_names": [
            "Enter_Fake_Wholesaler_Name_1"
        ],
        "stolen_registry_numbers": [
            "Enter_Stolen_TAX_ID_or_Company_Number", 
            "Enter_Stolen_KvK_Number"
        ],
        "corrupted_identity_strings": [
            "Enter_Corrupted_Code_Pasted_by_Fraudster_as_Registry_ID"
        ]
    }

    # 2. RUN THE SCANNER ON THE TARGET STORE
    target_website = "https://example-new-store-to-audit.com"
    
    detector = BallisticShieldDetector(target_url=target_website, fraud_db=FRAUD_DATABASE)
    report = detector.run_full_scan()
    
    print(json.dumps(report, indent=2, ensure_ascii=False))
