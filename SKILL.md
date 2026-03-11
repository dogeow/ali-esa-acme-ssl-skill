---
name: esa-dns-acme
description: 使用阿里云 ESA DNS + acme.sh 自动申请/续期 HTTPS 证书（含泛域名 *.example.com + example.com），并可自动安装到 Nginx。用户提到 ESA、ATrustDNS、_acme-challenge、acme.sh、Let's Encrypt、No TXT record found、InvalidRecordNameSuffix、通配符证书、Nginx 证书配置时务必使用本技能。
---

# ESA DNS + ACME 证书自动化（可发布版）

## 设计决策（重要）
本技能 **包含 acme.sh + ESA DNS** 一体化流程，不拆成两个 skill。

原因：
1. 这两个步骤强耦合：ACME challenge token 必须立刻写入 ESA DNS。
2. 用户最常见问题是“验证失败/解析写错面板”，一体化最少出错。
3. 泛域名场景经常出现同名多 TXT 值，拆开会增加人工同步成本。

> 如果未来有大量“仅 DNS 运维”需求，再拆分出 `esa-dns-records` 辅助 skill。

---

## 何时触发
当用户满足任一情况时触发：
- 域名 NS 在 `*.atrustdns.com`（ESA 托管 DNS）
- 说“用 acme.sh 申请证书”“Let's Encrypt”“DNS-01”
- 报错 `No TXT record found at _acme-challenge...`
- 需要 `example.com + *.example.com` 同时签发
- 需要自动写 ESA DNS 记录并安装到 Nginx

---

## 适用环境
- Linux 主机（推荐 Ubuntu/CentOS）
- 系统级 Nginx（LNMP/LAMP）
- 非 Docker 场景
- 不保证 Windows/macOS 兼容

## 前置依赖
首次建议执行：
```bash
curl https://get.acme.sh | sh
source ~/.bashrc
acme.sh --register-account -m example@example.com
acme.sh --set-default-ca --server letsencrypt
```

Python 依赖（脚本可自动安装；也可手动）：
```bash
python3 -m pip install --user aliyun-python-sdk-core aliyun-python-sdk-alidns
```

需要：
- 已安装 `acme.sh`
- AK/SK（建议临时环境变量传入）

说明：`SiteId` 默认自动按域名匹配，可用 `--site-id` 手动覆盖。

---

## 执行脚本
使用同目录脚本：
- `scripts/esa_acme_issue.py`

默认参数（已优化）：
- 自动按域名查询 `SiteId`（可用 `--site-id` 手动覆盖）
- 默认安装证书并重载 Nginx（可用 `--no-install-cert` 关闭）
- `--dns-timeout` 默认 600 秒
- 可选自动确保 A 记录：`--ensure-a-record host=ip`（含权威 NS 传播校验）
- 覆盖保护：存在旧 A 值时默认拒绝覆盖，必须显式传 `--confirm-overwrite`

### 单域名
```bash
export ALIYUN_AK='你的AK'
export ALIYUN_SK='你的SK'
python3 scripts/esa_acme_issue.py \
  -d g.example.com
```

### 主域 + 泛域（推荐顺序）
```bash
export ALIYUN_AK='你的AK'
export ALIYUN_SK='你的SK'
python3 scripts/esa_acme_issue.py \
  -d example.com \
  -d '*.example.com'
```

---

## Nginx 正确配置
```nginx
ssl_certificate     /etc/nginx/ssl/example.com.crt;
ssl_certificate_key /etc/nginx/ssl/example.com.key;
```

禁止把 `.csr` 当证书使用。

---

## 结果确认规则（防止“说成功但控制台没记录”）
在回复“解析已完成/记录已创建”之前，必须同时满足：
1) `ListRecords` 能查到目标 `RecordName + Type + Value`；
2) 权威 NS `dig @ns TXT` 能查到对应 token。

若只拿到 CreateRecord 的 API 返回（仅 RequestId/RecordId）但未通过上述两步，只能说“请求已提交”，不能说“已完成”。

## 故障排查速查
1. `InvalidRecordNameSuffix`
- 域名后缀不属于当前 ESA 站点（常见拼写错误）。

2. `No TXT record found at _acme-challenge...`
- TXT 尚未传播到所有权威 NS；调大 `--dns-timeout` 到 300~600。

3. `cannot load certificate ... .csr`
- 证书路径错了，用 `fullchain`/`.crt` + `.key`。

4. `ssl_stapling ignored`
- 非致命告警，不影响基础 HTTPS 可用。

5. AccessKey 设置了 IP 白名单后报权限/签名错误
- 先确认当前机器公网出口 IP：`curl -s ifconfig.me`
- 白名单应放行实际出口 NAT IP（不是内网 IP）
- 经代理/网关转发场景，放行代理出口 IP
- 白名单更新后等待短暂生效再重试

---

## 安全规范
每次执行前，提醒用户 1/2/3：
1) 优先使用 RAM 子账号最小权限，不要使用主账号长期 AK。
2) 优先使用 STS 临时凭证，降低泄漏风险。
3) 开启 AccessKey IP 白名单，仅放行实际出口 NAT IP。

- 不在脚本内硬编码 AK/SK。
- 优先使用环境变量注入。
- AK/SK 一旦在聊天或日志出现，立即轮换。
