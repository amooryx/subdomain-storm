import json, socket, urllib.request, urllib.error, concurrent.futures as cf, rclib

WORDS = ["www","mail","remote","vpn","api","dev","staging","test","admin","portal",
         "gateway","git","gitlab","jenkins","jira","confluence","autodiscover","owa",
         "smtp","imap","ns1","ns2","dns","cdn","assets","static","app","apps","secure",
         "login","auth","sso","adfs","exchange","citrix","rdp","ssh","ftp","db","sql",
         "backup","monitor","grafana","kibana","prometheus","internal","intranet","corp"]

def resolves(name):
    try: socket.getaddrinfo(name, None); return name
    except OSError: return None

def run(ctx):
    apex = ctx.target.lstrip("*.").lower()
    found = set()
    ctx.info("passive: crt.sh")
    try:
        req = urllib.request.Request(f"https://crt.sh/?q=%25.{apex}&output=json",
                                     headers={"User-Agent": "redcell"})
        for e in json.loads(urllib.request.urlopen(req, timeout=40).read()):
            for n in str(e.get("name_value","")).splitlines():
                n=n.strip().lstrip("*.").lower()
                if n.endswith(apex): found.add(n)
    except Exception as e:
        ctx.warn(f"crt.sh unavailable: {e}")
    ctx.info(f"active: resolving {len(WORDS)} common names")
    cand = [f"{w}.{apex}" for w in WORDS]
    with cf.ThreadPoolExecutor(max_workers=40) as ex:
        for r in ex.map(resolves, cand):
            if r: found.add(r)
    for n in sorted(found): ctx.good(n)
    ctx.data["subdomains"] = sorted(found)
    ctx.finding(f"{len(found)} live subdomains", "info", count=len(found))
    return 0

rclib.main("subdomain-storm", "Passive + active subdomain enumeration", run)
