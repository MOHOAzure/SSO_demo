# SSO 第二階段實現 - 完整安全版本

本目錄包含了完整的 SSO (Single Sign-On) 第二階段實現，具備生產級別的安全特性。

## 🏗️ 架構組件

### 1. Identity Provider (IdP) - `idp_app.py`
- **端口**: 8000
- **功能**: 身份驗證和授權服務器
- **端點**:
  - `GET /` - IdP 主頁
  - `GET /login` - 登錄頁面
  - `POST /login` - 登錄處理
  - `GET /authorize` - OIDC 授權端點
  - `POST /token` - OIDC 令牌端點
  - `GET /.well-known/jwks.json` - 公鑰分發 (JWKS)
  - `GET /.well-known/openid_configuration` - OpenID Connect Discovery
  - `POST /logout` - RP-Initiated Logout

### 2. Client Applications - `client1_app.py` & `client2_app.py`
- **端口**: 8001 (Client 1), 8002 (Client 2)
- **功能**: OIDC 客戶端應用程式
- **端點**:
  - `GET /` - 客戶端主頁
  - `GET /login` - 發起 SSO 登錄
  - `GET /callback` - OIDC 回調處理
  - `GET /profile` - 受保護的用戶資料頁面
  - `POST /logout` - 登出

## 🔒 第二階段安全特性

### 1. PKCE (Proof Key for Code Exchange)
- **目的**: 防止授權碼攔截攻擊
- **實現**: 
  - 客戶端生成 `code_verifier` (高熵隨機串)
  - 計算 `code_challenge = SHA256(code_verifier)`
  - IdP 驗證 `code_verifier` 與存儲的 `code_challenge` 匹配

### 2. State 參數透傳
- **目的**: 防止跨站請求偽造 (CSRF) 攻擊
- **實現**:
  - 客戶端生成隨機 `state` 參數
  - IdP 原樣返回 `state`
  - 客戶端驗證返回的 `state` 與發送的一致

### 3. Nonce 處理
- **目的**: 防止重放攻擊
- **實現**:
  - 客戶端生成隨機 `nonce` 參數
  - IdP 將 `nonce` 包含在 id_token 中
  - 客戶端驗證 id_token 中的 `nonce` 與發送的一致

### 4. RS256 簽名的 JWT
- **目的**: 確保令牌完整性和真實性
- **實現**:
  - IdP 使用 RSA 私鑰簽名 id_token
  - 客戶端使用 IdP 公鑰驗證簽名
  - 支持密鑰輪換 (通過 kid 標識)

### 5. JWKS (JSON Web Key Set) 端點
- **目的**: 安全分發驗證公鑰
- **實現**:
  - IdP 發布 `/.well-known/jwks.json` 端點
  - 客戶端動態獲取公鑰進行 JWT 驗證
  - 支持多個密鑰和密鑰輪換

### 6. 安全的會話管理
- **目的**: 保護用戶會話安全
- **實現**:
  - 使用簽名 JWT 作為會話 Cookie
  - 設置 `HttpOnly`, `Secure`, `SameSite=Lax` 屬性
  - 登錄後更新會話 ID (防會話固定攻擊)

### 7. 安全頭設置
- **目的**: 加強瀏覽器安全
- **實現**:
  - `Content-Security-Policy`: 限制腳本來源
  - `X-Frame-Options`: 防止點擊劫持
  - `X-Content-Type-Options`: 防止 MIME 類型嗅探
  - `Cache-Control`: 敏感頁面禁用緩存

## 🚀 運行系統

### 1. 環境準備
```bash
# 使用 uv (推薦)
uv sync                    # 安裝依賴
source .venv/bin/activate  # 激活虛擬環境
```

### 2. 啟動所有服務
```bash
chmod +x run.sh
uv run ./run.sh          # 使用 uv 運行
# 或
source .venv/bin/activate && ./run.sh
```

### 3. 運行測試
```bash
uv run python test_sso.py   # 使用 uv 運行
# 或
source .venv/bin/activate && python test_sso.py
```

## 🧪 測試流程

### 1. 基本 SSO 流程
1. 訪問 [http://localhost:8001](http://localhost:8001) (Client 1)
2. 點擊 "Login with SSO"
3. 在 IdP 登錄頁面輸入憑證:
   - 用戶名: `alice`, 密碼: `password123`
   - 或用戶名: `bob`, 密碼: `password456`
4. 登錄成功後自動重定向回 Client 1
5. 查看用戶資料頁面

### 2. 測試 Single Sign-On
1. 在 Client 1 登錄後
2. 直接訪問 [http://localhost:8002](http://localhost:8002) (Client 2)
3. ✨ **自動靜默完成登錄**
   - 後端自動檢測 IdP 會話狀態
   - 靜默完成授權碼交換
   - 直接顯示已登錄狀態
   - 完全無需用戶手動操作或看到未登錄狀態

### 3. 安全驗證檢查點
- 檢查授權 URL 包含正確的 PKCE 參數 (`code_challenge`, `code_challenge_method=S256`)
- 驗證 `state` 和 `nonce` 參數存在且為隨機值
- 確認 id_token 為有效的 JWT 格式
- 檢查會話 Cookie 設置了安全屬性
- 測試登出功能正確清除會話

## 📋 演示賬戶

| 用戶名 | 密碼 | 郵箱 | 姓名 |
|--------|------|------|------|
| alice | password123 | alice@example.com | Alice Smith |
| bob | password456 | bob@example.com | Bob Johnson |

## 🔧 配置說明

### IdP 配置
- **私鑰**: 自動生成並保存到 `idp_private_key.pem`
- **公鑰**: 自動生成並保存到 `idp_public_key.pem`
- **JWT 過期時間**: 30 分鐘
- **授權碼過期時間**: 10 分鐘

### 客戶端配置
- **Client 1 ID**: `client1`
- **Client 2 ID**: `client2`
- **重定向 URI**: `http://localhost:800X/callback`
- **會話過期時間**: 30 分鐘

## 🛡️ 安全注意事項

### 生產環境部署
1. **HTTPS**: 所有通信必須使用 HTTPS
2. **密鑰管理**: 使用專門的密鑰管理服務 (如 AWS KMS, HashiCorp Vault)
3. **環境變量**: 客戶端密鑰通過環境變量注入
4. **會話存儲**: 使用 Redis 等共享存儲實現會話管理
5. **監控**: 添加詳細的安全事件日誌和監控

### 已實現的攻擊防護
- ✅ 授權碼攔截攻擊 (PKCE)
- ✅ 跨站請求偽造 (State 參數)
- ✅ 重放攻擊 (Nonce 參數)
- ✅ JWT 簽名偽造 (RS256 + 公鑰驗證)
- ✅ 會話固定攻擊 (登錄後更新會話)
- ✅ 點擊劫持 (X-Frame-Options)
- ✅ 跨站腳本攻擊 (CSP)

## 📁 文件結構

```
SSO/
├── idp_app.py              # Identity Provider 服務器
├── client1_app.py          # 客戶端應用 1  
├── client2_app.py          # 客戶端應用 2
├── test_sso.py             # 系統測試腳本
├── unit_tests.py           # 單元測試
├── pyproject.toml          # uv 項目配置與依賴
├── uv.lock                 # 依賴鎖定文件
├── run.sh                  # 啟動腳本
├── idp_private_key.pem     # IdP 私鑰 (自動生成)
├── idp_public_key.pem      # IdP 公鑰 (自動生成)
└── templates/              # HTML 模板
    ├── idp_home.html       # IdP 主頁
    ├── idp_login.html      # IdP 登錄頁
    ├── client_home.html    # 客戶端主頁
    └── client_profile.html # 用戶資料頁
```

## 🔄 與第一階段的差異

| 特性 | 第一階段 (MVP) | 第二階段 (安全版) |
|------|----------------|-------------------|
| 授權碼保護 | ❌ 固定碼 | ✅ PKCE 驗證 |
| CSRF 保護 | ❌ 無 | ✅ State 參數 |
| 重放保護 | ❌ 無 | ✅ Nonce 參數 |
| JWT 簽名 | ❌ 未簽名 | ✅ RS256 簽名 |
| 公鑰分發 | ❌ 無 | ✅ JWKS 端點 |
| 會話安全 | ❌ 明文 Cookie | ✅ 簽名 JWT Cookie |
| 安全頭 | ❌ 無 | ✅ CSP, X-Frame-Options 等 |
| 登出 | ❌ 本地清理 | ✅ RP-Initiated Logout |

這個第二階段實現提供了完整的生產級安全特性，符合 OIDC 最佳實踐和安全標準。


## 補充

關於 Access Token 與資源服務器

儘管 IdP 會簽發 access_token，且客戶端也會接收它，但在當前的演示項目中，並沒有一個獨立的「資源服務器」。受保護的 /profile 頁面是客戶端應用的一部分，其訪問控制和數據展示僅依賴於對 id_token 的驗證。

在一個更完整的生產架構中，客戶端會使用收到的 access_token 作為 Bearer 令牌，去請求一個獨立的、受保護的後端 API (資源服務器) 來獲取數據。本項目為簡化起見，省略了這一步。