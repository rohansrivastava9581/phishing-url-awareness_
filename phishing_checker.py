import re
from typing import List
from urllib.parse import urlparse

# Defined standard warning messages as constants for clean architecture
FLAG_AT_SYMBOL = "Contains an @ symbol; inspect carefully."
FLAG_LONG_URL = "Unusually long URL (over 100 characters)."
FLAG_IP_HOST = "Uses an IP address instead of a familiar domain."
FLAG_MANY_SEGMENTS = "Contains many hostname segments/subdomains."
FLAG_PUNYCODE = "Contains a punycode-style hostname."
FLAG_INSECURE_HTTP = "Uses HTTP. HTTPS alone does not prove trust."
FLAG_NO_ISSUES = "No listed warning signs found. This does NOT prove safety."

def inspect_url(raw_url: str) -> List[str]:
    """
    Statically analyzes a URL string for common phish-related structural patterns.
     Does not establish network connections or resolve DNS schemas.
    """
    url: str = raw_url.strip()
    findings: List[str] = []
    
    if not url:
        return ["No URL entered."]
        
    # Standardize the URL scheme prefix so the engine can parse the host accurately
    candidate_url: str = url if "://" in url else f"http://{url}"
    
    try:
        parsed_data = urlparse(candidate_url)
    except ValueError:
        return ["This text is not a valid URL format."]
        
    hostname: str = (parsed_data.hostname or "").lower()
    if not hostname:
        return ["Could not identify a stable hostname structure."]
        
    # Rule 1: Evaluate embedded user authentication (@ character routing)
    if "@" in candidate_url:
        findings.append(FLAG_AT_SYMBOL)
        
    # Rule 2: Evaluate obfuscation string metrics
    if len(url) > 100:
        findings.append(FLAG_LONG_URL)
        
    # Rule 3: Evaluate numeric resolution properties (IPv4 format matching)
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname):
        findings.append(FLAG_IP_HOST)
        
    # Rule 4: Evaluate domain structure depth metrics
    domain_labels: List[str] = [part for part in hostname.split(".") if part]
    if len(domain_labels) >= 5:
        findings.append(FLAG_MANY_SEGMENTS)
        
    # Rule 5: Evaluate internationalized domain layout anomalies
    if "xn--" in hostname:
        findings.append(FLAG_PUNYCODE)
        
    # Rule 6: Evaluate transportation network security layers
    if parsed_data.scheme.lower() == "http":
        findings.append(FLAG_INSECURE_HTTP)
        
    return findings if findings else [FLAG_NO_ISSUES]


def main() -> None:
    """Application entry point handling runtime terminal loop execution."""
    print("=" * 50)
    print("      PHISHING URL HEURISTIC DETECTION ENGINE     ")
    print("   [Defensive Static Analysis Framework Only]   ")
    print("=" * 50)
    
    while True:
        try:
            user_input: str = input("\nEnter target URL syntax (or 'q' to terminate): ")
        except (KeyboardInterrupt, EOFError):
            print("\n\nExecution interrupted.")
            break
            
        if user_input.strip().lower() in ("q", "quit", "exit"):
            print("\nSession ended. Maintain defensive awareness online.")
            break
            
        print("\nAnalysis Metrics:")
        scan_results: List[str] = inspect_url(user_input)
        
        for warning in scan_results:
            print(f" [-] {warning}")
            
        # Professional Summary Block
        if scan_results and scan_results[0] not in (FLAG_NO_ISSUES, "No URL entered.", "This text is not a valid URL format."):
            print(f"\n[!] ALERT: Heuristic engine identified {len(scan_results)} compliance flags.")
            
        print("-" * 50)
        print("Note: Treat external inputs with zero trust models.")

if __name__ == "__main__":
    main()
