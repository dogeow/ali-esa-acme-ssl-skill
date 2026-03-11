# esa-dns-acme

一体化自动化技能：通过 **阿里云 ESA DNS + acme.sh** 申请/续期证书（支持 `example.com + *.example.com`），并可自动部署到 Nginx。

## 目录
- `SKILL.md`：技能触发与操作说明
- `scripts/esa_acme_issue.py`：自动化执行脚本
- `evals/evals.json`：基础评测样例

## 适用环境
- ✅ Linux（推荐 Ubuntu/CentOS）
- ✅ 传统主机部署（LNMP/LAMP，系统级 Nginx）
- ✅ 非容器环境（非 Docker）
- ❌ 不保证 Windows / macOS 直接可用
- ❌ 不保证 Docker 容器内自动安装与 reload 行为可用

## 首次初始化（acme.sh）
```bash
curl https://get.acme.sh | sh
source ~/.bashrc
acme.sh --register-account -m example@example.com
acme.sh --set-default-ca --server letsencrypt
```

## 快速开始

### 1) 依赖
脚本默认会自动安装 Python SDK 依赖；如你希望手动安装：
```bash
python3 -m pip install --user aliyun-python-sdk-core aliyun-python-sdk-alidns
```

### 2) 单域名
```bash
export ALIYUN_AK='你的AK'
export ALIYUN_SK='你的SK'
python3 scripts/esa_acme_issue.py \
  -d g.example.com
```

### 3) 泛域名
```bash
export ALIYUN_AK='你的AK'
export ALIYUN_SK='你的SK'
python3 scripts/esa_acme_issue.py \
  -d example.com \
  -d '*.example.com'
```

默认行为：
- 自动根据域名查询 ESA `SiteId`（可手动传 `--site-id` 覆盖）
- 默认自动安装证书到 Nginx（如不需要：`--no-install-cert`）
- `--dns-timeout` 默认 600 秒（可自行调整）

## 常见问题
- `No TXT record found`：增加 `--dns-timeout`，确认权威 NS 已生效
- `InvalidRecordNameSuffix`：域名不属于当前 ESA 站点后缀
- `cannot load certificate ... .csr`：误用 CSR，Nginx 应使用 `.crt/fullchain + .key`

## 安全
- 不要把 AK/SK 写进脚本
- 若 AK/SK 暴露，立即轮换
