import argparse
import concurrent.futures as cf
import http.client
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request

import rclib


WORDS = [
    "www", "mail", "remote", "vpn", "api", "dev", "staging", "test", "admin",
    "portal", "gateway", "git", "gitlab", "jenkins", "jira", "confluence",
    "autodiscover", "owa", "smtp", "imap", "ns1", "ns2", "dns", "cdn",
    "assets", "static", "app", "apps", "secure", "login", "auth", "sso",
    "adfs", "exchange", "citrix", "rdp", "ssh", "ftp", "db", "sql", "backup",
    "monitor", "grafana", "kibana", "prometheus", "internal", "intranet", "corp",
]
DEFAULT_TIMEOUT = 15.0
MAX_TIMEOUT = 60.0
MAX_THREADS = 50
MAX_WORDS = 10_000
MAX_CRT_RESPONSE_BYTES = 5 * 1024 * 1024
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _normalize_domain(value):
    domain = value.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("target is not a valid domain name") from exc
    if len(domain) > 253 or "." not in domain:
        raise ValueError("target must be a fully qualified domain name")
    if any(not _LABEL_RE.fullmatch(label) for label in domain.split(".")):
        raise ValueError("target contains an invalid DNS label")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("target must be a domain name, not an IP address")


def normalize_target(target):
    value = target.strip()
    if "://" in value:
        try:
            parsed = urllib.parse.urlsplit(value)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("target URL is invalid") from exc
        if parsed.scheme.lower() not in ("http", "https") or not hostname:
            raise ValueError("target URL must use HTTP or HTTPS and include a hostname")
        value = hostname
    return _normalize_domain(value)


def _normalize_label(label):
    try:
        ascii_label = label.strip().lower().encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return ascii_label if _LABEL_RE.fullmatch(ascii_label) else None


def load_wordlist(path):
    if not path:
        return WORDS
    labels = []
    seen = set()
    with open(path, encoding="utf-8") as word_file:
        for line_number, line in enumerate(word_file, 1):
            value = line.split("#", 1)[0].strip()
            if not value:
                continue
            label = _normalize_label(value)
            if label is None:
                raise ValueError(f"invalid DNS label on wordlist line {line_number}")
            if label not in seen:
                labels.append(label)
                seen.add(label)
                if len(labels) > MAX_WORDS:
                    raise ValueError(f"wordlist exceeds the {MAX_WORDS}-label limit")
    if not labels:
        raise ValueError("wordlist contains no DNS labels")
    return labels


def _is_subdomain(name, apex):
    try:
        candidate = _normalize_domain(name)
    except ValueError:
        return None
    if candidate != apex and candidate.endswith("." + apex):
        return candidate
    return None


def fetch_crtsh_names(apex, timeout):
    query = urllib.parse.urlencode({"q": f"%.{apex}", "output": "json"})
    request = urllib.request.Request(
        f"https://crt.sh/?{query}",
        headers={"User-Agent": "subdomain-storm/1.0 (authorized security testing)"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = response.read(MAX_CRT_RESPONSE_BYTES + 1)
    if len(payload) > MAX_CRT_RESPONSE_BYTES:
        raise ValueError(f"crt.sh response exceeds {MAX_CRT_RESPONSE_BYTES} bytes")
    entries = json.loads(payload.decode("utf-8"))
    if not isinstance(entries, list):
        raise ValueError("crt.sh returned an unexpected response format")

    names = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        value = entry.get("name_value")
        if not isinstance(value, str):
            continue
        for name in value.splitlines():
            candidate = _is_subdomain(name.strip().removeprefix("*."), apex)
            if candidate:
                names.add(candidate)
    return names


def resolves(name):
    try:
        socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
        return name
    except socket.gaierror:
        return None


def _positive_int(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number < 1 or number > MAX_THREADS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_THREADS}")
    return number


def _timeout(value):
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number of seconds") from exc
    if number <= 0 or number > MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(f"must be greater than 0 and at most {MAX_TIMEOUT}")
    return number


def add_arguments(parser):
    parser.add_argument(
        "--passive", action="store_true",
        help="use certificate-transparency data only; do not perform DNS lookups",
    )
    parser.add_argument("--wordlist", help="file containing one DNS label per line")
    parser.add_argument(
        "--threads", type=_positive_int, default=10,
        help=f"maximum concurrent DNS lookups (1-{MAX_THREADS}; default: 10)",
    )
    parser.add_argument(
        "--timeout", type=_timeout, default=DEFAULT_TIMEOUT,
        help=f"crt.sh request timeout in seconds (default: {DEFAULT_TIMEOUT:g}, max: {MAX_TIMEOUT:g})",
    )


def run(ctx):
    try:
        apex = normalize_target(ctx.target)
        words = [] if ctx.args.passive else load_wordlist(ctx.args.wordlist)
    except (OSError, ValueError) as exc:
        ctx.err(str(exc))
        return 2

    found = set()
    errors = []
    ctx.data["domain"] = apex
    ctx.data["sources"] = {}

    if not ctx.args.quiet:
        ctx.info("passive: querying crt.sh certificate-transparency data")
    try:
        passive = fetch_crtsh_names(apex, ctx.args.timeout)
        found.update(passive)
        ctx.data["sources"]["crt_sh"] = {"available": True, "count": len(passive)}
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException, UnicodeError,
            json.JSONDecodeError, ValueError) as exc:
        message = f"crt.sh unavailable: {exc}"
        errors.append(message)
        ctx.data["sources"]["crt_sh"] = {"available": False, "error": str(exc)}
        ctx.warn(message)

    resolved = set()
    if not ctx.args.passive:
        if not ctx.args.quiet:
            ctx.info(f"active: resolving {len(words)} common names (max {ctx.args.threads} concurrent)")
        candidates = (f"{word}.{apex}" for word in words)
        with cf.ThreadPoolExecutor(max_workers=ctx.args.threads) as executor:
            for name in executor.map(resolves, candidates):
                if name:
                    resolved.add(name)
        found.update(resolved)
        ctx.data["sources"]["dns"] = {"enabled": True, "count": len(resolved)}
    else:
        ctx.data["sources"]["dns"] = {"enabled": False, "count": 0}

    subdomains = sorted(found)
    resolved_names = sorted(resolved)
    ctx.data["subdomains"] = subdomains
    ctx.data["resolved_subdomains"] = resolved_names
    if not ctx.args.quiet:
        for name in subdomains:
            ctx.good(name)
    ctx.finding(
        f"{len(subdomains)} subdomains discovered",
        "info",
        passive=len(found - resolved),
        resolved=len(resolved),
    )
    if errors and ctx.args.passive:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(rclib.main(
        "subdomain-storm",
        "Bounded passive and DNS-based subdomain enumeration",
        run,
        extra_args=add_arguments,
        target_help="domain, wildcard domain, or HTTP(S) URL",
    ))
