# Subdomain Storm

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

> **High-speed async subdomain enumerator — brute-force + passive crt.sh/HackerTarget — with JSON/CSV output.**

## Usage

```bash
# Full enumeration (brute + passive)
python subdomain_storm.py example.com

# Passive only (crt.sh + HackerTarget)
python subdomain_storm.py example.com --passive

# Custom wordlist, 200 threads, JSON output
python subdomain_storm.py example.com --wordlist wordlist.txt --threads 200 --format json --out subs.json
```

## Disclaimer

> **Authorized security testing only.**

## Author

**Omar Khalid** — [omareldemery.com](https://omareldemery.com) | [@amooryx](https://github.com/amooryx)
