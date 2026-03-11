# ali-esa-acme-ssl-skill

[English](README.md)

OpenClaw 技能：使用 **阿里云 ESA DNS + acme.sh** 自动申请/续期 HTTPS 证书，支持泛域名，可自动安装到 Nginx。

## 解决什么问题

AI 模型总是解析到错误的地方，它到传统的云解析 DNS 那边解析，正确的应该是解析 ESA DNS，这两者是独立的。

也就是说，当域名托管在 ESA（`*.atrustdns.com`）时，DNS-01 验证记录必须写入 ESA DNS，而不是传统的云解析 DNS。

## 环境兼容性

- ✅ Linux 主机（Ubuntu 已测试）
- ✅ 系统级 Nginx（LNMP 已测试）
- ❌ 容器环境（不支持 Docker）
- ❌ 没有测试 Windows/macOS

## 项目结构

- `SKILL.md` – Agent 触发规则和使用指南
- `scripts/esa_acme_issue.py` – 自动化脚本
- `scripts/i18n/` – 脚本输出的语言文件（en.json、zh.json 等）
- `evals/evals.json` – 基础评估用例

## 首次安装 acme.sh

```bash
curl https://get.acme.sh | sh
source ~/.bashrc
acme.sh --register-account -m example@example.com
acme.sh --set-default-ca --server letsencrypt
```

## Python 依赖

脚本默认自动安装依赖。手动安装（可选）：

```bash
python3 -m pip install --user aliyun-python-sdk-core aliyun-python-sdk-alidns
```

## 快速开始

### 1) 导出凭证

```bash
export ALIYUN_AK='你的AK'
export ALIYUN_SK='你的SK'
```

### 2) 单域名

```bash
python3 scripts/esa_acme_issue.py -d test.example.com --lang zh
```

### 3) 主域 + 泛域名

```bash
python3 scripts/esa_acme_issue.py -d example.com -d '*.example.com' --lang zh
```

## 默认行为

- 默认安装证书到 Nginx（`--no-install-cert` 关闭）
- `--dns-timeout` 默认 `600`
- 可选 A 记录管理：`--ensure-a-record host=ip`（含权威 NS 传播验证）
- 覆盖保护：除非提供 `--confirm-overwrite`，否则不会覆盖已有 A 记录值

示例：

```bash
python3 scripts/esa_acme_issue.py \
  -d test.example.com \
  --ensure-a-record test.example.com=1.2.3.4 \
  --lang zh
```

## 完成判定标准（防误报）

在声明"DNS 记录已完成"之前，必须同时满足：

1. ESA `ListRecords` 确认了精确的 `RecordName + Type + Value`
2. 权威 NS 查询（`dig @ns TXT`）返回了预期的 token

如果仅 CreateRecord API 返回成功，应报告为"请求已接受"（非已完成）。

## 常见故障排查

- `No TXT record found`：增大 `--dns-timeout`，验证权威 NS 传播
- `InvalidRecordNameSuffix`：域名不属于当前 ESA 站点后缀

## 常见问题

### Q: 我给 AccessKey 设置了 IP 白名单，应该检查什么？

A: 这是"权限"类错误的常见原因。

- 确保服务器当前的 **公网出口 IP** 在白名单中
- 如果使用代理/NAT，白名单应放行 **实际出口 NAT IP**，而非内网 IP
- 先确认出口 IP：

  ```bash
  curl -s ifconfig.me
  ```

## 安全说明

每次执行前，始终提醒用户以下 1/2/3：

1. 使用最小权限 RAM 子账号密钥，避免长期使用主账号密钥
2. 尽可能优先使用 STS 临时凭证
3. 为 AccessKey 开启 IP 白名单，只放行实际出口 NAT IP

- 不要在脚本中硬编码 AK/SK
- 优先使用环境变量
- 一旦 AK/SK 在聊天或日志中暴露，立即轮换
