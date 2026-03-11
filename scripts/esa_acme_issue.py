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


def redact_text(text, secrets=None):
    out = text or ""
    secrets = [s for s in (secrets or []) if s]
    for s in secrets:
        out = out.replace(s, "***REDACTED***")
    # basic AccessKeyId pattern mask
    out = re.sub(r"LTAI[0-9A-Za-z]{12,}", "LTAI***REDACTED***", out)
    return out


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


def wait_record_visible_in_esa(client, site_id, fqdn, token, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = esa_req(client, "ListRecords", "GET", SiteId=site_id)
            records = resp.get("Records", [])
            for r in records:
                if r.get("RecordName") == fqdn and r.get("RecordType") == "TXT":
                    val = ((r.get("Data") or {}).get("Value") or "")
                    if val == token:
                        return True, r.get("RecordId")
        except Exception:
            pass
        time.sleep(3)
    return False, None


def pick_main_domain(domains):
    # Prefer non-wildcard as main domain for acme.sh storage/install path
    for d in domains:
        if not d.startswith("*."):
            return d
    return domains[0].lstrip("*.")


def wait_a_record(zone, host, expected_ip, timeout=300):
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        code, out = run(f"for ns in $(dig +short NS {zone}); do echo '== '$ns' =='; dig +short A {host} @$ns; done")
        last = out
        blocks = [b.strip() for b in out.split('== ') if b.strip()]
        ok_all = True
        for b in blocks:
            if expected_ip not in b:
                ok_all = False
                break
        if ok_all and blocks:
            return True, out
        time.sleep(5)
    return False, last


def ensure_a_record(client, site_id, zone, host, ip, dns_timeout=600, confirm_overwrite=False):
    records = esa_req(client, "ListRecords", "GET", SiteId=site_id).get("Records", [])
    target = None
    for r in records:
        if r.get("RecordName") == host and r.get("RecordType") == "A/AAAA":
            target = r
            break
    payload = json.dumps({"Value": ip}, separators=(",", ":"))
    if target:
        current = ((target.get("Data") or {}).get("Value") or "").strip()
        if current and current != ip and not confirm_overwrite:
            print(f"[CONFIRM] Existing A record detected: {host} -> {current}")
            print(f"[CONFIRM] Requested new value: {ip}")
            print("[ERR] overwrite blocked. Re-run with --confirm-overwrite after user confirmation.")
            sys.exit(6)
        esa_req(client, "UpdateRecord", "POST", SiteId=site_id, RecordId=target.get("RecordId"), Type="A/AAAA", RecordName=host, Ttl=1, Data=payload, Proxied="false")
        print(f"[INFO] A record update request accepted: {host} -> {ip}")
    else:
        esa_req(client, "CreateRecord", "POST", SiteId=site_id, Type="A/AAAA", RecordName=host, Ttl=1, Data=payload, Proxied="false")
        print(f"[INFO] A record create request accepted: {host} -> {ip}")

    ok, out = wait_a_record(zone, host, ip, timeout=dns_timeout)
    if not ok:
        print(out)
        print(f"[ERR] A record not propagated on all authoritative NS: {host} -> {ip}")
        sys.exit(4)
    print(f"[OK] A record propagated on authoritative NS: {host} -> {ip}")


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
    print(redact_text(out))
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


def print_security_reminders(has_sts_token):
    print("[SECURITY] 请提醒用户以下 1/2/3：")
    print("  1) 优先使用 RAM 子账号最小权限，不要使用主账号长期 AK。")
    print("  2) 优先使用 STS 临时凭证（短时有效），降低泄漏风险。")
    print("  3) 开启 AccessKey IP 白名单，仅放行实际出口 NAT IP。")
    if not has_sts_token:
        print("[SECURITY][WARN] 当前未检测到 STS SecurityToken，疑似长期 AK/SK。")


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
    ap.add_argument("--ensure-a-record", action="append", default=[], help="ensure A/AAAA record, format: host=ip")
    ap.add_argument("--confirm-overwrite", action="store_true", default=False, help="required to overwrite existing A/AAAA record value")
    args = ap.parse_args()

    ensure_python_deps(auto_install=args.auto_install_deps)
    from aliyunsdkcore.client import AcsClient

    if not args.ak or not args.sk:
        print("[ERR] missing --ak/--sk (or env ALIYUN_AK/ALIYUN_SK)")
        sys.exit(2)

    sts_token = os.getenv("ALIYUN_SECURITY_TOKEN") or os.getenv("SECURITY_TOKEN")
    print_security_reminders(bool(sts_token))
    secrets = [args.ak, args.sk, sts_token]

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

    # optional: ensure A records before cert flow
    for item in args.ensure_a_record:
        if "=" not in item:
            print(f"[ERR] invalid --ensure-a-record format: {item}, expect host=ip")
            sys.exit(2)
        host, ip = item.split("=", 1)
        host = host.strip()
        ip = ip.strip()
        ensure_a_record(client, site_id, zone, host, ip, dns_timeout=args.dns_timeout, confirm_overwrite=args.confirm_overwrite)

    # 1) get challenge token(s) via manual dns mode
    d_args = " ".join([f"-d '{d}'" for d in issue_domains])
    issue_cmd = f"'{acme_sh}' --issue --dns {d_args} --yes-I-know-dns-manual-mode-enough-go-ahead-please --keylength ec-256"
    code, out = run(issue_cmd)
    challenges = parse_challenges(out)
    if not challenges:
        print(redact_text(out, secrets))
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
                print(f"[INFO] ESA API accepted create request: {fqdn} token={token[:10]}... RecordId={rid}")

                visible, confirmed_rid = wait_record_visible_in_esa(client, site_id, fqdn, token, timeout=120)
                if not visible:
                    print(f"[ERR] ESA record not visible after create: {fqdn} token={token}")
                    print("[ERR] Do NOT claim DNS is ready. Please check ESA console/API permissions/filters.")
                    sys.exit(4)

                record_ids.append(confirmed_rid or rid)
                print(f"[OK] ESA TXT confirmed in ListRecords: {fqdn} RecordId={confirmed_rid or rid}")

        # 3) wait propagation for each token on each fqdn
        for fqdn, tokens in grouped.items():
            for token in tokens:
                ok, out = wait_txt(zone, fqdn, token, timeout=args.dns_timeout)
                if not ok:
                    print(redact_text(out, secrets))
                    print(f"[ERR] TXT not propagated: {fqdn} token={token}")
                    sys.exit(4)
            print(f"[OK] authoritative TXT visible: {fqdn} ({len(tokens)} value(s))")

        # 4) renew/sign (manual mode requires renew after issue)
        renew = f"'{acme_sh}' --renew -d '{main_domain}' --yes-I-know-dns-manual-mode-enough-go-ahead-please --keylength ec-256"
        code, out = run(renew)
        print(redact_text(out, secrets))
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
            print(redact_text(out, secrets))
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
