# ali-esa-acme-ssl-skill

OpenClaw skill for **automatic HTTPS certificate issuance/renewal** using **Alibaba Cloud ESA DNS + acme.sh**, with optional automatic installation to Nginx.

## What this skill solves

When domains are hosted on ESA (`*.atrustdns.com`), DNS-01 records must be written to ESA DNS, not traditional AliDNS.
This skill standardizes that workflow and reduces common errors like:

- `No TXT record found at _acme-challenge...`
- `InvalidRecordNameSuffix`
- Misusing `.csr` as Nginx certificate

## Environment compatibility

- ✅ Linux hosts (recommended: Ubuntu/CentOS)
- ✅ System-level Nginx deployments (LNMP/LAMP)
- ✅ Non-container environments
- ⚠️ Not guaranteed on Windows/macOS
- ⚠️ Not guaranteed inside Docker for install/reload behavior

## Project structure

- `SKILL.md` – Trigger rules and usage guidance for the agent
- `scripts/esa_acme_issue.py` – Automation script
- `evals/evals.json` – Basic evaluation prompts

## First-time acme.sh setup

```bash
curl https://get.acme.sh | sh
source ~/.bashrc
acme.sh --register-account -m example@example.com
acme.sh --set-default-ca --server letsencrypt
```

## Python dependencies

The script can auto-install dependencies by default. Manual install (optional):

```bash
python3 -m pip install --user aliyun-python-sdk-core aliyun-python-sdk-alidns
```

## Quick start

### 1) Export credentials

```bash
export ALIYUN_AK='YOUR_AK'
export ALIYUN_SK='YOUR_SK'
```

### 2) Single domain

```bash
python3 scripts/esa_acme_issue.py -d g.example.com
```

### 3) Apex + wildcard

```bash
python3 scripts/esa_acme_issue.py -d example.com -d '*.example.com'
```

## Defaults

- Auto-detect ESA `SiteId` by domain suffix (override with `--site-id`)
- Auto-install cert to Nginx by default (disable with `--no-install-cert`)
- `--dns-timeout` default is `600`

## Common troubleshooting

- `No TXT record found`: increase `--dns-timeout`, verify authoritative NS propagation
- `InvalidRecordNameSuffix`: domain does not belong to current ESA site suffix
- `cannot load certificate ... .csr`: use `.crt/fullchain + .key`, not CSR

## Security notes

- Never hardcode AK/SK in script
- Prefer env vars
- Rotate keys immediately if exposed in chat/logs
