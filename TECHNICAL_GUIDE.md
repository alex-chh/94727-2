# Shadow Credentials 技術深度指南

## 🎯 技術核心原理

### 什麼是 Shadow Credentials？
Shadow Credentials 是一種 Active Directory 持久化技術，通過修改目標物件的 `msDS-KeyCredentialLink` 屬性，植入攻擊者的公鑰憑證，實現基於 PKINIT 的 Kerberos 認證繞過。

### 攻擊鏈分解
```
1. 權限獲取 → 2. AD物件修改 → 3. 憑證生成 → 4. PKINIT認證 → 5. 權限提升
```

## 🔧 技術細節深度解析

### msDS-KeyCredentialLink 屬性結構
```
B:828:00020000200001F0CFD96144615BB05AB8B47F60612B1E4A0DBFD55A6ADB712F4E09BD942E4EAB200002108E27456151CEEE8835141AABF619BD525C29276A32C695348AEDAF65BAF6251B0103525341310008000003000000000100000000000000000000010001EF597D9ADE406639441ED656862CFAE28E19AA44E8490AE811D5AF94C27D522AA56F8B138DA7F15DF4CF084185D84026CD38636751CA15AFBFB5672A0D2B8555620F10D8A707B2E8859CC6C13F4471B864638AACEBE03804A352DAC203FE3017873E373FC0DA07258D5D052307987E4C9BC0DEE4ED4C64BF90D26ED4E4F50409E871ABADF160C37D4F2AC541C9099FFC3E24A8DB0A421E4CAC57A6A601FE7F4B917591F8AA96E9F1B16054B21A6BFEF133A11CFBBA53388E6AFAA7114950A7BDF48D48294526DA221A9258829D94D49597BC7FC3AC50B5EA0581BBEF1445619401ACC705C097064A0AD67267FF40F425417E81D11680630076EB6E8DBF22CF4501000401010005001000068114AE80D3D7AE4BB3CE4C8EC654BA790200070100080008E52FBDA152ACDC01080009E52FBDA152ACDC01:CN=Target,CN=Computers,DC=domain,DC=local
```

### PKINIT 認證流程
1. **AS-REQ**: 客戶端發送包含 PA-PK-AS-REQ 的請求
2. **KDC 驗證**: KDC 驗證憑證有效性
3. **AS-REP**: KDC 返回加密的 TGT
4. **後續認證**: 使用 TGT 進行正常 Kerberos 流程

## 🛡️ EDR 偵測技術要點

### 高價值偵測點

#### 1. AD 物件修改偵測
```powershell
# 監控事件 ID
- 5136: Directory Service Changes
- 4662: Object Access  
- 4742: Computer Account Changed
- 4738: User Account Changed

# 關鍵屬性監控
msDS-KeyCredentialLink
msDS-SupportedEncryptionTypes
```

#### 2. 憑證操作偵測
```powershell
# 檔案監控路徑
C:\Windows\Temp\shadow*.pfx
C:\Users\*\AppData\Local\Temp\shadow*.pfx

# 憑證內容特徵
- 自簽名憑證
- 特定 EKU (Client Authentication)
- 短有效期
```

#### 3. 工具執行偵測
```powershell
# 程序名稱
Whisker.exe
Rubeus.exe

# 命令列特徵
/certificate:
/password:
/getcredentials
/domain:
/dc:
```

#### 4. 網路活動偵測
```powershell
# Kerberos 流量特徵
- 目的端口: 88/tcp
- 協定: Kerberos
- 內容: PKINIT pa-data

# 失敗特徵
KDC_ERR_PADATA_TYPE_NOSUPP
KDC_ERR_ETYPE_NOSUPP
```

## 🔍 進階偵測策略

### 行為關聯分析
```
1. AD寫入 + 憑證生成 + PKINIT嘗試 = 高置信度攻擊
2. 單獨事件可能需要上下文關聯
```

### 時間序列分析
```
時間窗口: 5分鐘內發生以下事件序列
- T+0: Whisker.exe 執行
- T+30s: AD物件修改  
- T+1m: PFX檔案建立
- T+2m: Rubeus.exe PKINIT嘗試
```

### 憑證指紋分析
```powershell
# 偵測特徵
- 非企業CA簽發
- 特定主題名稱格式
- 短有效期 (1-7天)
- 特定金鑰用法
```

## 🧪 測試案例設計

### 基礎測試案例
```yaml
- name: 電腦帳號 Shadow Credentials
  steps:
    - Whisker add 電腦帳號
    - Rubeus asktgt AES256
    - 驗證AD修改偵測
    - 驗證憑證操作偵測
    - 驗證網路活動偵測

- name: 使用者帳號 Shadow Credentials  
  steps:
    - Whisker add 使用者帳號
    - Rubeus asktgt AES256
    - 驗證相同偵測點
```

### 進階測試案例
```yaml
- name: 混合攻擊鏈測試
  steps:
    - Kerberoasting 獲取憑據
    - Shadow Credentials 持久化
    - Golden Ticket 利用
    - 驗證端到端偵測能力

- name: 規避技術測試
  steps:
    - 記憶體執行工具
    - 憑證檔案混淆
    - 網路流量加密
    - 驗證進階偵測能力
```

## 📊 效能與擴展性

### 測試規模建議
```yaml
小型測試: 1-5個目標物件
中型測試: 5-20個目標物件  
大型測試: 20+個目標物件
```

### 自動化測試框架
```python
# 偽代碼範例
def test_shadow_credentials_edr():
    # 初始化測試環境
    setup_test_environment()
    
    # 執行攻擊鏈
    execute_attack_chain()
    
    # 收集EDR告警
    alerts = collect_edr_alerts()
    
    # 驗證偵測效果
    assert ad_modification_detected(alerts)
    assert certificate_operation_detected(alerts) 
    assert network_activity_detected(alerts)
    
    # 清理環境
    cleanup_environment()
```

## 🚨 常見問題與解決方案

### Q: KDC_ERR_PADATA_TYPE_NOSUPP 錯誤
**原因**: KDC 不支援或拒絕 PKINIT
**解決**: 不影響EDR驗證，專注於行為偵測

### Q: 權限不足
**原因**: 缺乏對目標物件的寫入權限
**解決**: 先獲取適當權限或使用有權限的帳號

### Q: EDR 無告警
**原因**: 偵測規則未啟用或需要調整
**解決**: 檢查EDR配置，調整偵測靈敏度

### Q: 環境污染
**原因**: 測試後未正確清理
**解決**: 嚴格執行環境還原流程

## 🔧 故障排除指南

### 診斷步驟
1. **權限驗證**: 確認對目標AD物件的寫入權限
2. **工具驗證**: 確認Whisker/Rubeus工具正常運作
3. **網路驗證**: 確認與KDC的網路連通性
4. **EDR驗證**: 確認EDR監控功能正常運作

### 日誌分析
```powershell
# Windows 事件日誌
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=5136 or EventID=4662)]]"
Get-WinEvent -LogName System -FilterXPath "*[System[(EventID=4742 or EventID=4738)]]"

# EDR 日誌
檢查EDR特定的日誌檔案和資料庫
```

### 效能優化
```yaml
# 建議配置
- 記憶體: 8GB+ for EDR +測試環境
- CPU: 4核心+ 
- 儲存: SSD推薦
- 網路: 1Gbps+

# 並發測試
- 循序測試: 確保事件順序正確
- 並發測試: 測試EDR處理能力
```

## 📈 度量與報告

### 關鍵效能指標
```yaml
detection_rate: 偵測率
false_positive_rate: 誤報率  
response_time: 回應時間
coverage: 偵測覆蓋率
```

### 報告範本
```markdown
# Shadow Credentials EDR 測試報告

## 執行摘要
- 測試日期: [日期]
- 測試環境: [環境描述]
- EDR產品: [產品名稱版本]

## 測試結果
| 偵測類型 | 偵測率 | 誤報率 | 回應時間 |
|---------|--------|--------|----------|
| AD修改偵測 | 100% | 0% | <1s |
| 憑證操作偵測 | 100% | 0% | <1s |
| 工具執行偵測 | 100% | 0% | <1s |
| 網路活動偵測 | 100% | 0% | <1s |

## 詳細發現
[具體偵測情況描述]

## 建議改進
[EDR配置或規則調整建議]
```

## 🔮 未來擴展方向

### 技術演進
- 支援更多憑證類型
- 增強規避技術偵測
- 改進行為分析算法

### 整合擴展
- 與SIEM系統整合
- 支援更多EDR平台
- 自動化測試流水線

### 標準化推進
- 貢獻MITRE ATT&CK
- 建立業界標準測試用例
- 提供開源測試框架

---

*本技術指南提供深入的 Shadow Credentials 技術細節和EDR偵測策略，幫助安全團隊建立完整的偵測和驗證能力。*