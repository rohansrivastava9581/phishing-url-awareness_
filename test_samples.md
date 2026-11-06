# Test Results

Python version used: 3.11+ | Operating system: Windows/Mac | Date: 2026-11-04

| # | Input | Expected result | Actual result | Pass/Fail |
|---|-------|-----------------|---------------|-----------|
| 1 | https://example.com | No listed warning signs | No listed warning signs found. This does NOT prove safety. | PASS |
| 2 | http://192.0.2 | IP address + HTTP | Uses an IP address; Uses HTTP | PASS |
| 3 | http://sample.invalid | @ symbol + HTTP | Contains an @ symbol; Uses HTTP | PASS |
| 4 | https://example.invalid | Many hostname segments | Contains many hostname segments/subdomains. | PASS |
| 5 | https://xn--example.invalid | Punycode-style hostname | Contains a punycode-style hostname. | PASS |

## Notes
- The program evaluates URL patterns locally without establishing any external network connections.
- Flagging zero warning signs does not guarantee that a link is entirely authentic or safe.
