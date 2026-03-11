#!/usr/bin/env python3
import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time



def run(cmd):
    p = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    return p.returncode, p.stdout + p.stderr


def esa_req(client, action, method="POST", **params):
    from aliyunsdkcore.request import CommonRequest
    req = CommonRequest()
    req.set_accept_format("json")
    req.set_domain("esa.cn-hangzhou.aliyuncs.com")
    req.set_version("2024-09-10")
    req.set_action_name(action)
    req.set_method(method)
    req.set_protocol_type("https")
    for k, v in params.items():
        req.add_query_param(k, str(v))
    return json.loads(client.do_action_with_exception(req).decode())


def parse_challenges(output):
    # acme.sh manual mode prints repeated blocks:
    # Domain: 'xxx'
    # TXT value: 'yyy'
    pairs = re.findall(r"Domain:\s*'([^']+)'[\s\S]*?TXT value:\s*'([^']+)'", output)
    return [{"fqdn": d, "token": t} for d, t in pairs]


def wait_txt(zone, fqdn, expected, timeout=240):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        code, out = run(f"for ns in $(dig +short NS {zone}); do echo '== '$ns' =='; dig +short TXT {fqdn} @$ns; done")
        last = out
        # require all authoritative NS answers to include expected token
        blocks = [b.strip() for b in out.split('== ') if b.strip()]
        ok_all = True
        for b in blocks:
            if expected not in b:
                ok_all = False
                break
        if ok_all and blocks:
            return True, out
        time.sleep(5)
    return False, last


def pick_main_domain(domains):
    # Prefer non-wildcard as main domain for acme.sh storage/install path
    for d in domains:
        if not d.startswith("*."):
            return d
    return domains[0].lstrip("*.")


def auto_site_id(client, base_domain):
    # Find best matching site by suffix, prefer exact domain match
    page = 1
    candidates = []
    while True:
        resp = esa_req(client, "ListSites", "GET", PageNumber=page, PageSize=500)
        sites = resp.get("Sites", [])
        for s in sites:
            sn = (s.get("SiteName") or "").lower().strip()
            if not sn:
                continue
            if base_domain == sn or base_domain.endswith("." + sn):
                candidates.append(s)
        total = int(resp.get("TotalCount", 0) or 0)
        if page * 500 >= total:
            break
        page += 1

    if not candidates:
        raise RuntimeError(f"No ESA site matched domain: {base_domain}")

    candidates.sort(key=lambda s: len((s.get("SiteName") or "")), reverse=True)
    return str(candidates[0].get("SiteId")), candidates[0].get("SiteName")


def ensure_python_deps(auto_install=True):
    needed = ["aliyunsdkcore"]
    missing = [m for m in needed if importlib.util.find_spec(m) is None]
    if not missing:
        return
    if not auto_install:
        print("[ERR] missing python deps: aliyun-python-sdk-core / aliyun-python-sdk-alidns")
        sys.exit(2)
    print("[INFO] installing python deps...")
    code, out = run("python3 -m pip install --user aliyun-python-sdk-core aliyun-python-sdk-alidns")
    print(out)
    if code != 0:
        print("[ERR] failed to auto-install python deps")
        sys.exit(2)


def find_acme_sh():
    cands = [os.path.expanduser("~/.acme.sh/acme.sh"), shutil.which("acme.sh")]
    for c in cands:
        if c and os.path.exists(c):
            return c
    print("[ERR] acme.sh not found. Install acme.sh first.")
    sys.exit(2)


def main():
    ap = argparse.ArgumentParser(description="Issue cert via acme.sh + ESA DNS TXT automation (supports wildcard)")
    ap.add_argument("-d", "--domain", action="append", required=True, help="can repeat, e.g. -d example.com -d '*.example.com'")
    ap.add_argument("--site-id", required=False, help="ESA site id (optional; auto-detect by domain if omitted)")
    ap.add_argument("--ak", default=os.getenv("ALIYUN_AK"))
    ap.add_argument("--sk", default=os.getenv("ALIYUN_SK"))
    ap.add_argument("--auto-install-deps", dest="auto_install_deps", action="store_true", default=True)
    ap.add_argument("--no-auto-install-deps", dest="auto_install_deps", action="store_false")
    ap.add_argument("--ttl", default="60")
    ap.add_argument("--dns-timeout", type=int, default=600)
    ap.add_argument("--install-cert", dest="install_cert", action="store_true", default=True)
    ap.add_argument("--no-install-cert", dest="install_cert", action="store_false")
    ap.add_argument("--cert-path", default=None, help="target crt path")
    ap.add_argument("--key-path", default=None, help="target key path")
    ap.add_argument("--reload-cmd", default="systemctl reload nginx")
    args = ap.parse_args()

    ensure_python_deps(auto_install=args.auto_install_deps)
    from aliyunsdkcore.client import AcsClient

    if not args.ak or not args.sk:
        print("[ERR] missing --ak/--sk (or env ALIYUN_AK/ALIYUN_SK)")
        sys.exit(2)

    # de-dup while preserving order
    domains = list(dict.fromkeys(args.domain))
    main_domain = pick_main_domain(domains)
    issue_domains = [main_domain] + [d for d in domains if d != main_domain]

    acme_sh = find_acme_sh()
    client = AcsClient(args.ak, args.sk, "cn-hangzhou")

    # Resolve site id/site name
    base_domain = main_domain.lstrip("*.")
    if args.site_id:
        site_id = str(args.site_id)
        zone = base_domain
        try:
            site = esa_req(client, "GetSite", "POST", SiteId=site_id)
            zone = (site.get("SiteName") or base_domain)
        except Exception:
            pass
    else:
        site_id, zone = auto_site_id(client, base_domain)
        print(f"[OK] auto-detected SiteId={site_id} for site={zone}")

    # 1) get challenge token(s) via manual dns mode
    d_args = " ".join([f"-d '{d}'" for d in issue_domains])
    issue_cmd = f"'{acme_sh}' --issue --dns {d_args} --yes-I-know-dns-manual-mode-enough-go-ahead-please --keylength ec-256"
    code, out = run(issue_cmd)
    challenges = parse_challenges(out)
    if not challenges:
        print(out)
        print("[ERR] failed to parse challenge tokens")
        sys.exit(3)

    print("[OK] challenges:")
    for c in challenges:
        print(f"  - {c['fqdn']} = {c['token']}")

    # group by fqdn (apex + wildcard often share same fqdn but different token)
    grouped = {}
    for c in challenges:
        grouped.setdefault(c["fqdn"], [])
        if c["token"] not in grouped[c["fqdn"]]:
            grouped[c["fqdn"]].append(c["token"])

    record_ids = []
    try:
        # 2) create ESA TXT for each challenge token
        for fqdn, tokens in grouped.items():
            for token in tokens:
                rec = esa_req(
                    client,
                    "CreateRecord",
                    "POST",
                    SiteId=site_id,
                    RecordName=fqdn,
                    Type="TXT",
                    Ttl=args.ttl,
                    Data=json.dumps({"Value": token}, separators=(",", ":")),
                    Proxied="false",
                )
                rid = rec.get("RecordId")
                record_ids.append(rid)
                print(f"[OK] ESA TXT created: {fqdn} token={token[:10]}... RecordId={rid}")

        # 3) wait propagation for each token on each fqdn
        for fqdn, tokens in grouped.items():
            for token in tokens:
                ok, out = wait_txt(zone, fqdn, token, timeout=args.dns_timeout)
                if not ok:
                    print(out)
                    print(f"[ERR] TXT not propagated: {fqdn} token={token}")
                    sys.exit(4)
            print(f"[OK] authoritative TXT visible: {fqdn} ({len(tokens)} value(s))")

        # 4) renew/sign (manual mode requires renew after issue)
        renew = f"'{acme_sh}' --renew -d '{main_domain}' --yes-I-know-dns-manual-mode-enough-go-ahead-please --keylength ec-256"
        code, out = run(renew)
        print(out)
        if code != 0:
            print("[ERR] renew/sign failed")
            sys.exit(5)

        # 5) optional install
        if args.install_cert:
            cert_src = f"/root/.acme.sh/{main_domain}_ecc/fullchain.cer"
            key_src = f"/root/.acme.sh/{main_domain}_ecc/{main_domain}.key"
            cert_dst = args.cert_path or f"/etc/nginx/ssl/{main_domain}.crt"
            key_dst = args.key_path or f"/etc/nginx/ssl/{main_domain}.key"
            run(f"install -m 600 '{key_src}' '{key_dst}'")
            run(f"install -m 644 '{cert_src}' '{cert_dst}'")
            code, out = run(args.reload_cmd)
            print(out)
            if code == 0:
                print(f"[OK] installed to {cert_dst}, {key_dst}")
            else:
                print("[WARN] install done but reload failed")

    finally:
        # 6) cleanup TXT
        for rid in record_ids:
            if not rid:
                continue
            try:
                esa_req(client, "DeleteRecord", "POST", SiteId=site_id, RecordId=rid)
                print(f"[OK] cleaned TXT RecordId={rid}")
            except Exception as e:
                print(f"[WARN] cleanup failed RecordId={rid}: {e}")


if __name__ == "__main__":
    main()
