---
name: ali-esa-acme-ssl-skill
description: Automatically issue/renew HTTPS certificates using Alibaba Cloud ESA DNS + acme.sh (including wildcard *.example.com + example.com), with optional auto-install to Nginx. Trigger this skill when the user mentions ESA, ATrustDNS, _acme-challenge, acme.sh, Let's Encrypt, No TXT record found, InvalidRecordNameSuffix, wildcard certificate, or Nginx certificate configuration.
---

# ESA DNS + ACME Certificate Automation

[中文版](SKILL_zh.md)

## Design Decision (Important)
This skill **combines acme.sh + ESA DNS** into a single integrated flow, not split into two skills.

Reasons:
1. The two steps are tightly coupled: ACME challenge tokens must be written to ESA DNS immediately.
2. The most common user errors are "validation failed / record written to the wrong panel" — an integrated flow minimizes mistakes.
3. Wildcard scenarios often produce multiple TXT values for the same FQDN; splitting would increase manual synchronization cost.

> If there is significant demand for "DNS-only operations" in the future, a separate `esa-dns-records` helper skill can be extracted.

---

## When to Trigger
Trigger when any of the following apply:
- Domain NS records are on `*.atrustdns.com` (ESA-hosted DNS)
- User says "issue certificate with acme.sh", "Let's Encrypt", "DNS-01"
- Error: `No TXT record found at _acme-challenge...`
- Need to issue `example.com + *.example.com` together
- Need to auto-write ESA DNS records and install to Nginx

---

## Supported Environment

- Linux hosts (recommended: Ubuntu tested)
- System-level Nginx (LNMP tested)
- Non-Docker scenarios
- Not tested on Windows/macOS

## Prerequisites

First-time setup:
```bash
curl https://get.acme.sh | sh
source ~/.bashrc
acme.sh --register-account -m example@example.com
acme.sh --set-default-ca --server letsencrypt
```

Python dependencies (the script can auto-install; or install manually):

```bash
python3 -m pip install --user aliyun-python-sdk-core aliyun-python-sdk-alidns
```

Requirements:

- AK/SK (recommended: pass via temporary environment variables)

---

## Running the Script

Script path: `scripts/esa_acme_issue.py`

Default behavior (optimized):

- Auto-install cert and reload Nginx (disable with `--no-install-cert`)
- `--dns-timeout` defaults to 600 seconds
- Optional A record management: `--ensure-a-record host=ip` (with authoritative NS propagation check)
- Overwrite protection: existing A value is NOT overwritten unless `--confirm-overwrite` is passed
- `--lang` selects output language (default: `en`; available languages auto-discovered from `scripts/i18n/`)

### Single domain

```bash
export ALIYUN_AK='YOUR_AK'
export ALIYUN_SK='YOUR_SK'
python3 scripts/esa_acme_issue.py \
  -d test.example.com
```

### Apex + wildcard (recommended order)

```bash
export ALIYUN_AK='YOUR_AK'
export ALIYUN_SK='YOUR_SK'
python3 scripts/esa_acme_issue.py \
  -d example.com \
  -d '*.example.com'
```

---

## Correct Nginx Configuration

```nginx
ssl_certificate     /etc/nginx/ssl/example.com.crt;
ssl_certificate_key /etc/nginx/ssl/example.com.key;
```

---

## Completion Criteria (Anti False-Positive)
Before reporting "record created / DNS ready", both conditions must be met:

1) `ListRecords` returns the target `RecordName + Type + Value`;
2) Authoritative NS `dig @ns TXT` returns the expected token.

If only the CreateRecord API returned success (RequestId/RecordId only) without passing both checks above, report "request accepted", not "completed".

## Troubleshooting Quick Reference

1. `InvalidRecordNameSuffix`
   - Domain suffix does not belong to the current ESA site (common typo).

2. `No TXT record found at _acme-challenge...`
   - TXT not yet propagated to all authoritative NS; increase `--dns-timeout` to 300–600.

3. Permission / signature errors after setting AccessKey IP whitelist
   - Check current public egress IP: `curl -s ifconfig.me`
   - Whitelist the actual egress NAT IP (not LAN IP)
   - If behind proxy/gateway, whitelist the proxy egress IP
   - Wait briefly after whitelist update before retrying

---

## Security Guidelines

Before each execution, remind the user:
1) Use a RAM sub-account with minimal permissions. Do NOT use the primary account long-term AK.
2) Prefer STS temporary credentials to reduce leak risk.
3) Enable AccessKey IP whitelist, allowing only the actual egress NAT IP.
