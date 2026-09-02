#!/usr/bin/env python3
"""
Subdomain Storm — High-speed async subdomain enumerator with multi-source validation.
Author: Omar Khalid (amooryx) | github.com/amooryx/subdomain-storm
AUTHORIZED USE ONLY — for authorized red team engagements and bug bounty.
"""

import argparse
import asyncio
import csv
import json
import os
import socket
import sys
import time
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

# ─── Config ───────────────────────────────────────────────────────────────────
DEFAULT_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "ns", "ww1", "host", "support", "dev", "web", "bbs", "ww42", "api",
    "mx", "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2",
    "gw", "admin", "store", "mx1", "cdn", "static", "app", "media", "new",
    "staging", "beta", "v2", "git", "svn", "jenkins", "jira", "confluence",
    "monitor", "proxy", "gateway", "internal", "intranet", "corp", "vpn2",
    "remote2", "citrix", "rdp", "aws", "azure", "gcp", "k8s", "docker",
]

CRTSH_URL  = "https://crt.sh/?q=%.{domain}&output=json"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

results_lock = Lock()
all_found: list[dict] = []

# ─── DNS resolution (threaded) ────────────────────────────────────────────────
def resolve(subdomain: str, timeout: float = 3.0) -> dict | None:
    try:
        socket.setdefaulttimeout(timeout)
        ips = socket.gethostbyname_ex(subdomain)[2]
        return {"subdomain": subdomain, "ips": ips, "source": "dns"}
    except Exception:
        return None

# ─── crt.sh passive discovery ─────────────────────────────────────────────────
def fetch_crtsh(domain: str) -> list[str]:
    url = CRTSH_URL.format(domain=domain)
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            entries = json.loads(resp.read())
            found = set()
            for e in entries:
                for name in e.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
            return list(found)
    except Exception:
        return []

# ─── HackerTarget passive discovery ───────────────────────────────────────────
def fetch_hackertarget(domain: str) -> list[str]:
    url = HACKERTARGET_URL.format(domain=domain)
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            text = resp.read().decode()
            found = []
            for line in text.splitlines():
                parts = line.split(",")
                if parts:
                    name = parts[0].strip().lower()
                    if name.endswith(f".{domain}"):
                        found.append(name)
            return found
    except Exception:
        return []

# ─── Main enumeration ──────────────────────────────────────────────────────────
def brute_force(domain: str, wordlist: list[str], threads: int, timeout: float) -> list[dict]:
    subdomains = [f"{w}.{domain}" for w in wordlist]
    found = []
    print(f"[*] Brute-forcing {len(subdomains)} subdomains with {threads} threads...")

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futures = {exe.submit(resolve, s, timeout): s for s in subdomains}
        for i, fut in enumerate(futures, 1):
            result = fut.result()
            if result:
                found.append(result)
                ips_str = ", ".join(result["ips"])
                print(f"  [+] {result['subdomain']:50s}  {ips_str}")
            if i % 100 == 0:
                print(f"  ... {i}/{len(subdomains)} checked, {len(found)} found so far")
    return found

def passive_enum(domain: str) -> list[dict]:
    print("[*] Passive enum via crt.sh ...")
    crt_subs = fetch_crtsh(domain)
    print(f"  [+] crt.sh: {len(crt_subs)} candidates")

    print("[*] Passive enum via HackerTarget ...")
    ht_subs  = fetch_hackertarget(domain)
    print(f"  [+] HackerTarget: {len(ht_subs)} candidates")

    all_subs = list(set(crt_subs + ht_subs))
    validated = []
    print(f"[*] Resolving {len(all_subs)} passive candidates...")
    with ThreadPoolExecutor(max_workers=50) as exe:
        futures = {exe.submit(resolve, s): s for s in all_subs}
        for fut in futures:
            result = fut.result()
            if result:
                result["source"] = "passive"
                validated.append(result)
                ips_str = ", ".join(result["ips"])
                print(f"  [+] {result['subdomain']:50s}  {ips_str}")
    return validated

def output_results(results: list[dict], fmt: str, outfile: str | None):
    if fmt == "json":
        text = json.dumps(results, indent=2)
    elif fmt == "csv":
        import io
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=["subdomain", "ips", "source"])
        w.writeheader()
        for r in results:
            w.writerow({"subdomain": r["subdomain"], "ips": ", ".join(r["ips"]), "source": r["source"]})
        text = buf.getvalue()
    else:
        text = "\n".join(r["subdomain"] for r in results)

    if outfile:
        with open(outfile, "w") as f:
            f.write(text)
        print(f"\n[*] Results saved to {outfile}")
    else:
        print("\n" + text)

# ─── Entry ────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Storm — Fast Subdomain Enumerator (Authorized use only)",
    )
    parser.add_argument("domain",          help="Target domain (e.g. example.com)")
    parser.add_argument("--wordlist", "-w", help="Wordlist file (one entry per line)")
    parser.add_argument("--threads",  "-t", type=int, default=100, help="Concurrent threads for brute-force")
    parser.add_argument("--timeout",        type=float, default=3.0, help="DNS timeout per query (seconds)")
    parser.add_argument("--passive",  "-p", action="store_true", help="Enable passive enumeration (crt.sh, HackerTarget)")
    parser.add_argument("--brute",    "-b", action="store_true", help="Enable brute-force enumeration")
    parser.add_argument("--all",      "-a", action="store_true", help="Enable both passive and brute-force")
    parser.add_argument("--format",   "-f", choices=["text", "json", "csv"], default="text")
    parser.add_argument("--out",      "-o", help="Output file")
    args = parser.parse_args()

    if not (args.passive or args.brute or args.all):
        args.all = True  # default: run everything

    start = time.time()
    results = []

    if args.passive or args.all:
        results.extend(passive_enum(args.domain))

    if args.brute or args.all:
        wordlist = DEFAULT_WORDLIST
        if args.wordlist:
            with open(args.wordlist) as f:
                wordlist = [l.strip() for l in f if l.strip()]
        results.extend(brute_force(args.domain, wordlist, args.threads, args.timeout))

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        if r["subdomain"] not in seen:
            seen.add(r["subdomain"])
            unique.append(r)

    elapsed = time.time() - start
    print(f"\n[*] Done in {elapsed:.1f}s | {len(unique)} unique live subdomains found")
    output_results(unique, args.format, args.out)

if __name__ == "__main__":
    main()
