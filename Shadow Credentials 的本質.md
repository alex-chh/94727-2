# Shadow Credentials 的本質

【核心概念】
Shadow Credentials 的本質就是：**「我不知道你的密碼，但我強行給你的帳號綁定了一張『備用身分證』(Certificate)，然後用這張身分證去騙取你的所有權限。」**

這是一個標準的 **「植入 -> 認證 -> 提取」** 資料流過程。

## 1. 植入階段 (The Implant)
**工具：pywhisker**
**動作：修改 `msDS-KeyCredentialLink`**

*   **現狀**：目標物件 (Target) 只有一個密碼 (NTLM Hash)，你不知道它是什麼。
*   **操作**：
    1.  你生成一對鑰匙：**公鑰 (Public Key)** 和 **私鑰 (Private Key)**。
    2.  你告訴 AD：「嘿，這個目標物件多了一個驗證方式，這是他的公鑰。」(寫入 `msDS-KeyCredentialLink` 屬性)。
    3.  AD 說：「好，我記住了。」
*   **結果**：你手上的 **PFX 文件** 就是那把私鑰。現在，你擁有了目標的第二個合法登入憑證。

## 2. 認證階段 (The Authentication)
**工具：PKINIT (gettgtpkinit.py)**
**動作：用 PFX 換取 TGT**

*   **問題**：通常登入 Kerberos 需要密碼 (用密碼加密時間戳)。你沒有密碼。
*   **解法 (PKINIT)**：
    1.  你用 **PFX (私鑰)** 對時間戳進行數位簽章。
    2.  你把簽章發給 KDC (網域控制站)。
    3.  KDC 拿出你在第一步存的 **公鑰** 驗證簽章。
    4.  KDC 確認：「簽章正確，你是合法的。」
*   **結果**：KDC 發給你一張 **TGT (Ticket Granting Ticket)**。
    *   *關鍵點*：這張 TGT 證明了你是該用戶，而且包含了一個由 KDC 生成的 **Session Key (會話密鑰)**。因為是你發起的 PKINIT，只有你和 KDC 知道這個 Session Key。

## 3. 提取階段 (The Extraction / The Magic)
**工具：U2U (getnthash.py)**
**動作：用 TGT 換取 NT Hash**

這一步是最精彩的駭客魔法。你有了 TGT，但你真正想要的是 NTLM Hash (為了做 Pass-the-Hash 或製作 Silver Ticket)。

*   **問題**：NTLM Hash 在哪裡？它被藏在 Kerberos 票據內部的 PAC (Privilege Attribute Certificate) 結構中，通常用來支援舊版 NTLM 驗證。
*   **操作 (User-to-User, U2U)**：
    1.  你拿著剛拿到的 TGT，對 KDC 說：「我要申請一張訪問 **我自己** 的服務票據 (Service Ticket)。」
    2.  並且你指定：「請用我們剛才協商好的 **Session Key** 來加密這張票據。」
    3.  KDC 照做，把包含你用戶資訊 (PAC) 的票據用 Session Key 加密後發給你。
*   **結果**：
    1.  你收到票據。
    2.  你用手上的 Session Key 解密票據。
    3.  你打開 PAC 結構，直接讀取裡面的 `GSS_CHECKSUM` 或 `PAC_CREDENTIAL_INFO` 欄位。
    4.  **Bingo! 裡面躺著該用戶的 NTLM Hash。**

---

## 總結圖解

```text
[攻擊者]                  [Active Directory / KDC]
   |                                 |
   | 1. (pywhisker)                  |
   | 生成公私鑰，寫入公鑰 ------------->| 修改 msDS-KeyCredentialLink
   | 擁有 PFX (私鑰) <----------------|
   |                                 |
   | 2. (PKINIT)                     |
   | 用 PFX 簽名請求 ------------------>| 驗證公鑰
   |                                 | 生成 Session Key
   | 收到 TGT + Session Key <--------|
   |                                 |
   | 3. (U2U / getnthash)            |
   | 用 TGT 請求"給自己"的票據 --------->|
   | (要求用 Session Key 加密)         |
   |                                 | 放入 NTLM Hash 到 PAC
   | 收到加密票據 <--------------------| 用 Session Key 加密票據
   |                                 |
   | 4. (本地解密)                    |
   | 用 Session Key 解開票據           |
   | 讀取 PAC -> 拿到 NTLM Hash       |
```

**這就是為什麼 PKINIT 失敗 (KDC 不支援) 會導致攻擊中斷：**
如果第 2 步失敗，你就拿不到 TGT 和 Session Key。沒有 Session Key，你就無法要求 KDC 加密包含 Hash 的票據給你，也就無法解密拿到 NTLM Hash。
