# SSO 系統監控與可觀測性設計文檔

## 核心監控指標速查表

### IdP 端必看指標

#### 1. **哪些 Client 訪問過我的 IdP？**
```promql
# 查看所有訪問過的 client
idp_authorization_code_issued_total

# 範例輸出：
idp_authorization_code_issued_total{client_id="client1"} 45
idp_authorization_code_issued_total{client_id="client2"} 23
idp_authorization_code_issued_total{client_id="unknown_client"} 2
```
**用途**：知道有哪些客戶端在使用您的 IdP 服務

#### 2. **哪個 Client 在亂搞？（跨部門溝通證據）**
```promql
# 查看所有 token 交換失敗的 client
idp_token_exchange_total{status="failure"}

# 按錯誤類型分組
sum(idp_token_exchange_total{status="failure"}) by (client_id, error_type)

# 範例輸出：
idp_token_exchange_total{client_id="client1", status="failure", error_type="pkce_failed"} 12
idp_token_exchange_total{client_id="client2", status="failure", error_type="invalid_code"} 8
idp_token_exchange_total{client_id="client1", status="failure", error_type="code_already_used"} 3
```

**常見錯誤類型與含義**：
- `pkce_failed`: Client 的 code_verifier 不匹配（**Client 實現錯誤**）
- `invalid_code`: Client 使用了不存在的授權碼（**Client 亂傳參數**）
- `code_already_used`: Client 重複使用授權碼（**Client 重試邏輯錯誤**）
- `code_expired`: Client 授權碼過期才來換 token（**Client 處理太慢**）
- `client_id_mismatch`: Client ID 不匹配（**Client 配置錯誤**）

#### 3. **誰在暴力破解登錄？**
```promql
# 登錄失敗次數（按用戶名分組）
idp_login_attempts_total{status="failure"}

# 範例輸出：
idp_login_attempts_total{status="failure", username="admin"} 156
idp_login_attempts_total{status="failure", username="root"} 89
idp_login_attempts_total{status="failure", username="alice"} 2
```
**用途**：檢測暴力破解攻擊、異常登錄行為

#### 4. **IdP 性能如何？（是否拖慢整體系統）**
```promql
# 各端點的 95th 百分位延遲
histogram_quantile(0.95, 
  rate(idp_http_request_duration_seconds_bucket[5m])
) by (endpoint)

# 範例輸出：
{endpoint="/token"} 0.045      # 45ms
{endpoint="/authorize"} 0.023   # 23ms
{endpoint="/login"} 0.012       # 12ms
```
**告警閾值建議**：超過 500ms 需要關注

---

### Client 端必看指標

#### 5. **我的 Client 是否正常工作？**
```promql
# Callback 成功率
rate(client_callback_total{status="success"}[5m]) 
/ 
rate(client_callback_total[5m])

# 範例：成功率 = 0.98 (98%)
```

#### 6. **Client 與 IdP 通信是否正常？**
```promql
# Client 調用 IdP 的失敗次數
client_callback_total{status="failure"}

# 按錯誤類型分組
sum(client_callback_total{status="failure"}) by (client, error_type)

# 範例輸出：
client_callback_total{client="client1", status="failure", error_type="token_exchange_failed"} 5
client_callback_total{client="client2", status="failure", error_type="jwt_verification_failed"} 2
```

---

## 實戰場景：如何用這些指標跨部門溝通

### 場景 1：Client 團隊說「IdP 有問題」
**您的證據**：
```bash
# 1. 檢查該 client 的錯誤
curl http://localhost:9090/metrics | grep 'idp_token_exchange_total.*client1.*failure'

# 輸出範例：
idp_token_exchange_total{client_id="client1",status="failure",error_type="pkce_failed"} 45.0

# 2. 回應話術：
"根據監控數據，client1 在過去 1 小時有 45 次 PKCE 驗證失敗。
這是 Client 端的 code_verifier 計算錯誤，請檢查你們的 PKCE 實現。
IdP 端 /token 接口正常，成功率 99.2%。"
```

### 場景 2：懷疑某個 Client 在測試環境亂搞
**您的證據**：
```bash
# 查看所有 client 的請求量
curl http://localhost:9090/metrics | grep 'idp_authorization_code_issued_total'

# 輸出範例：
idp_authorization_code_issued_total{client_id="client1"} 120.0
idp_authorization_code_issued_total{client_id="client2"} 85.0
idp_authorization_code_issued_total{client_id="test_client_dev"} 9876.0  # ← 異常！

# 回應話術：
"test_client_dev 在 1 小時內請求了 9876 次授權碼，
是正常流量的 80 倍，請開發團隊檢查是否有死循環或壓測未關閉。"
```

### 場景 3：老板問「我們的 SSO 穩定嗎？」
**您的報告**：
```
過去 24 小時 SSO 系統健康報告：
- IdP 可用性：99.98%
- 登錄成功率：98.5% (失敗主要是用戶密碼錯誤)
- Token 交換成功率：99.2%
- 注意事項：client3 有 12 次 PKCE 失敗，已通知該團隊修復
- 平均響應時間：/token 35ms, /authorize 18ms
```

---

## 文檔概述

本文檔定義了 SSO 系統（IdP 與 Client 應用）的監控與可觀測性實現標準。設計遵循業界最佳實踐，支持與 Prometheus、Grafana、Loki 等外部監控平台無縫對接。

**重要聲明**：本專案僅負責暴露監控指標與結構化日誌，不包含 Prometheus、Grafana、Loki 等監控系統的部署與配置代碼。

---

## 監控端點安全架構

### 生產級最佳實踐：端口隔離

**核心原則**：監控端點（`/metrics`）絕不能暴露在公共網絡，必須使用網絡層隔離保護。

#### 實現方案：雙端口架構

```
┌─────────────────────────────────────┐
│   IdP 服務器 (多進程架構)            │
│                                     │
│   進程 1: 主應用                     │
│   ├─ 綁定: 0.0.0.0:8000 (公開)      │
│   ├─ 端點: /authorize, /token, /login │
│   └─ /metrics → 返回 404 + 說明     │
│                                     │
│   進程 2: 監控服務                   │
│   ├─ 綁定: 127.0.0.1:9090 (僅本機)  │
│   ├─ 端點: /metrics (Prometheus)    │
│   └─ 端點: /health (健康檢查)       │
└─────────────────────────────────────┘
         ▲                    ▲
         │                    │
    公網訪問              內網訪問
    (用戶/客戶端)        (Prometheus)
```

#### 為什麼不使用應用層 IP 白名單？

**不推薦的做法**:
```python
# 錯誤示範：應用層 IP 檢查
@app.get("/metrics")
async def metrics(request: Request):
    if request.client.host not in ["127.0.0.1"]:
        return 403
    return generate_latest()
```

**問題**：
1. `request.client.host` 在負載均衡器/反向代理後不可靠
2. 可能被 X-Forwarded-For 等 header 欺騙
3. 應用層是最後防線，不應是唯一防線
4. 默認不安全（需要配置才安全）

**正確做法：網絡層隔離**
```python
# 正確示範：綁定到 localhost
metrics_app = FastAPI()

@metrics_app.get("/metrics")
async def metrics():
    return Response(content=generate_latest())

# 僅監聽本機
uvicorn.run(metrics_app, host="127.0.0.1", port=9090)
```

**優勢**：
- OS 層面強制隔離，無法從外部訪問
- 默認安全（無需配置）
- 配合防火牆/VPC/NetworkPolicy 形成多層防護
- 符合行業標準（Prometheus 官方推薦）

### 部署環境保護措施

#### Docker 環境
```yaml
# docker-compose.yml
services:
  idp:
    ports:
      - "8000:8000"      # 公開
    expose:
      - "9090"           # 僅 Docker 內部網絡
    networks:
      - public
      - monitoring

  prometheus:
    networks:
      - monitoring       # 只能訪問 monitoring 網絡
```

#### Kubernetes 環境
```yaml
# NetworkPolicy: 僅允許 Prometheus 訪問 metrics
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: idp-metrics-policy
spec:
  podSelector:
    matchLabels:
      app: idp
  ingress:
    - from:
      - podSelector:
          matchLabels:
            app: prometheus
      ports:
        - protocol: TCP
          port: 9090
```

#### 防火牆規則（裸機/虛擬機）
```bash
# 允許公共訪問 8000
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT

# 僅允許 localhost 訪問 9090
iptables -A INPUT -p tcp --dport 9090 ! -s 127.0.0.1 -j DROP
```

---

## 架構定位

### 系統角色
- **IdP 與 Client 應用**：Prometheus 的 **Target**（被監控方），被動暴露 `/metrics` 端點供 Prometheus 抓取
- **Prometheus**：主動從 IdP/Client 的 `/metrics` 端點拉取（Pull）指標數據
- **Grafana**：從 Prometheus 查詢數據並可視化展示
- **Loki**：從應用的結構化日誌（JSON 格式）中提取與索引日誌事件

### 監控範圍
1. **IdP（身份提供者）**：必須監控，作為 SSO 核心組件
2. **Client 應用（Client1, Client2）**：必須監控，用於診斷問題定位（區分 IdP 側或 Client 側故障）

---

## 技術棧與依賴

### 新增 Python 函式庫

在 `pyproject.toml` 或 `requirements.txt` 中添加以下依賴：

```toml
[project.dependencies]
# ... 現有依賴 ...
prometheus-client = "^0.20.0"  # Prometheus metrics 客戶端
python-json-logger = "^2.0.7"  # 結構化 JSON 日誌
```

### 函式庫用途
- **prometheus-client**：暴露 `/metrics` 端點，記錄業務指標（Counters, Histograms, Gauges）
- **python-json-logger**：將日誌輸出為 JSON 格式，方便 Loki 解析與索引

---

## IdP 監控設計

### 業務指標（Prometheus Metrics）

#### 1. 登錄嘗試統計
```python
# Metric 類型: Counter
# Metric 名稱: idp_login_attempts_total
# Labels: {status="success|failure", username="<username>"}
# 用途: 統計用戶登錄成功/失敗次數，檢測暴力破解攻擊
```

**實現範例**：
```python
from prometheus_client import Counter

login_attempts = Counter(
    'idp_login_attempts_total',
    'Total number of login attempts',
    ['status', 'username']
)

# 使用方式
login_attempts.labels(status='success', username='alice').inc()
login_attempts.labels(status='failure', username='bob').inc()
```

#### 2. 授權碼頒發統計
```python
# Metric 類型: Counter
# Metric 名稱: idp_authorization_code_issued_total
# Labels: {client_id="<dynamic>"}
# 用途: 統計各 Client 的授權碼頒發次數，動態識別所有客戶端
```

**實現範例**：
```python
from prometheus_client import Counter

auth_code_issued = Counter(
    'idp_authorization_code_issued_total',
    'Total number of authorization codes issued',
    ['client_id']
)

# 使用方式（動態 client_id，絕不寫死）
auth_code_issued.labels(client_id=request_client_id).inc()
```

#### 3. 令牌交換統計
```python
# Metric 類型: Counter
# Metric 名稱: idp_token_exchange_total
# Labels: {client_id="<dynamic>", status="success|failure", error_type="invalid_code|pkce_failed|expired|..."}
# 用途: 統計 /token 端點的成功與失敗情況，細分錯誤類型
```

**實現範例**：
```python
from prometheus_client import Counter

token_exchange = Counter(
    'idp_token_exchange_total',
    'Total number of token exchange attempts',
    ['client_id', 'status', 'error_type']
)

# 成功案例
token_exchange.labels(client_id='client1', status='success', error_type='none').inc()

# 失敗案例
token_exchange.labels(client_id='client2', status='failure', error_type='pkce_failed').inc()
```

#### 4. API 請求延遲
```python
# Metric 類型: Histogram
# Metric 名稱: idp_http_request_duration_seconds
# Labels: {method="GET|POST", endpoint="/login|/authorize|/token|/logout", status_code="200|302|400|..."}
# Buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
# 用途: 追蹤各端點的響應時間分佈，檢測性能瓶頸
```

**實現範例**：
```python
from prometheus_client import Histogram
import time

http_request_duration = Histogram(
    'idp_http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint', 'status_code'],
    buckets=[0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
)

# 使用方式（中間件或裝飾器）
start_time = time.time()
# ... 處理請求 ...
duration = time.time() - start_time
http_request_duration.labels(
    method='POST',
    endpoint='/token',
    status_code='200'
).observe(duration)
```

#### 5. 當前活躍會話數
```python
# Metric 類型: Gauge
# Metric 名稱: idp_active_sessions
# Labels: 無
# 用途: 實時顯示當前有效的 IdP 會話數量（需要在 Cookie 中追蹤或使用共享存儲）
# 注意: 在無狀態架構中，此指標實現複雜度較高，可作為可選項
```

### 結構化日誌（Loki）

所有日誌必須使用 **JSON 格式** 輸出，包含以下標準字段：

```json
{
  "timestamp": "2025-10-19T12:34:56.789Z",
  "level": "INFO",
  "service": "idp",
  "event": "login_success",
  "user_id": "user_alice_001",
  "username": "alice",
  "client_id": "client1",
  "remote_ip": "127.0.0.1",
  "duration_ms": 123.45,
  "message": "User alice logged in successfully"
}
```

**關鍵事件清單**：
1. **login_success** / **login_failure**：記錄 username, client_id（如有）, remote_ip, failure_reason（失敗時）
2. **authorization_code_issued**：記錄 client_id, user_id, prompt（normal/none）
3. **token_exchange_success** / **token_exchange_failure**：記錄 client_id, user_id, error_type（失敗時）
4. **logout**：記錄 user_id, client_id（從 id_token_hint 提取）

**禁止記錄的敏感信息**：
- 用戶密碼（password）
- 授權碼（authorization code）
- Access Token / ID Token 完整內容
- code_verifier / code_challenge

---

## Client 監控設計

### 業務指標（Prometheus Metrics）

#### 1. Callback 處理統計
```python
# Metric 類型: Counter
# Metric 名稱: client_callback_total
# Labels: {status="success|failure", error_type="missing_state_cookie|state_mismatch|token_exchange_failed|jwt_verification_failed|..."}
# 用途: 統計 /callback 端點的成功與失敗情況
```

#### 2. 與 IdP 通信延遲
```python
# Metric 類型: Histogram
# Metric 名稱: client_idp_request_duration_seconds
# Labels: {endpoint="/token|/.well-known/jwks.json", status="success|failure"}
# Buckets: [0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
# 用途: 監控 Client 調用 IdP 後端端點的延遲
```

#### 3. 本地會話驗證失敗統計
```python
# Metric 類型: Counter
# Metric 名稱: client_session_verification_failures_total
# Labels: {reason="missing_cookie|signature_verification_failed|expired"}
# 用途: 追蹤本地會話驗證失敗的原因分佈
```

### 結構化日誌（Loki）

```json
{
  "timestamp": "2025-10-19T12:35:10.123Z",
  "level": "ERROR",
  "service": "client1",
  "event": "callback_failure",
  "error_type": "state_mismatch",
  "remote_ip": "127.0.0.1",
  "message": "State parameter mismatch in callback"
}
```

**關鍵事件清單**：
1. **callback_success** / **callback_failure**：記錄 error_type, duration_ms
2. **token_exchange_request**：記錄調用 IdP /token 的延遲與結果
3. **jwt_verification_failure**：記錄具體的驗證失敗原因（簽名錯誤、過期、nonce 不匹配等）

---

## 實現要求

### /metrics 端點實現

所有服務（IdP, Client1, Client2）必須暴露 `/metrics` 端點：

```python
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from fastapi import Response

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint"""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
```

### 日誌配置範例

```python
import logging
from pythonjsonlogger import jsonlogger

# 配置 JSON 日誌格式
logger = logging.getLogger("idp")
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter(
    '%(timestamp)s %(level)s %(service)s %(event)s %(message)s',
    rename_fields={"levelname": "level", "asctime": "timestamp"}
)
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)

# 使用方式
logger.info(
    "User logged in successfully",
    extra={
        "event": "login_success",
        "service": "idp",
        "user_id": "user_alice_001",
        "username": "alice",
        "client_id": "client1",
        "remote_ip": "127.0.0.1"
    }
)
```

### 中間件整合（請求延遲追蹤）

```python
import time
from starlette.middleware.base import BaseHTTPMiddleware

class PrometheusMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start_time = time.time()
        response = await call_next(request)
        duration = time.time() - start_time
        
        http_request_duration.labels(
            method=request.method,
            endpoint=request.url.path,
            status_code=response.status_code
        ).observe(duration)
        
        return response

# 註冊中間件
app.add_middleware(PrometheusMiddleware)
```

---

## 外部監控系統配置指引

### Prometheus 抓取配置（參考）

本專案不包含 Prometheus 的部署，以下為外部配置參考：

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'sso_idp'
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'sso_clients'
    static_configs:
      - targets: ['localhost:8001', 'localhost:8002']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Loki 日誌收集（參考）

使用 Promtail 或 Docker logging driver 收集 stdout 的 JSON 日誌：

```yaml
# promtail-config.yml
clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: sso
    static_configs:
      - targets:
          - localhost
        labels:
          job: sso
          __path__: /var/log/sso/*.log
    pipeline_stages:
      - json:
          expressions:
            level: level
            service: service
            event: event
```

---

## 告警規則範例（參考）

以下為 Prometheus AlertManager 規則參考，不包含在本專案中：

```yaml
# alerts.yml
groups:
  - name: sso_alerts
    interval: 30s
    rules:
      # 登錄失敗率過高
      - alert: HighLoginFailureRate
        expr: |
          rate(idp_login_attempts_total{status="failure"}[5m]) 
          / 
          rate(idp_login_attempts_total[5m]) > 0.3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High login failure rate detected"
          description: "Login failure rate is {{ $value | humanizePercentage }} in the last 5 minutes"

      # Token 交換失敗率過高
      - alert: HighTokenExchangeFailureRate
        expr: |
          sum(rate(idp_token_exchange_total{status="failure"}[5m])) by (client_id, error_type) > 5
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "High token exchange failure rate for client {{ $labels.client_id }}"
          description: "Error type: {{ $labels.error_type }}, rate: {{ $value }} req/s"

      # IdP 響應時間過慢
      - alert: SlowIdPResponse
        expr: |
          histogram_quantile(0.95, 
            rate(idp_http_request_duration_seconds_bucket{endpoint="/token"}[5m])
          ) > 1.0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "IdP /token endpoint is slow"
          description: "95th percentile response time: {{ $value }}s"
```

---

## Grafana 儀表板設計（參考）

推薦創建以下儀表板面板：

### IdP 儀表板
1. **登錄成功率時間序列圖**：`rate(idp_login_attempts_total{status="success"}[5m])` vs `rate(idp_login_attempts_total{status="failure"}[5m])`
2. **按 Client 分組的授權碼頒發量**：`sum(rate(idp_authorization_code_issued_total[5m])) by (client_id)`
3. **Token 交換錯誤分佈餅圖**：`sum(idp_token_exchange_total{status="failure"}) by (error_type)`
4. **各端點響應時間熱圖**：`idp_http_request_duration_seconds_bucket`

### Client 儀表板
1. **Callback 成功率**：`rate(client_callback_total{status="success"}[5m])` vs `rate(client_callback_total{status="failure"}[5m])`
2. **與 IdP 通信延遲**：`histogram_quantile(0.95, rate(client_idp_request_duration_seconds_bucket[5m]))`
3. **會話驗證失敗原因分佈**：`sum(client_session_verification_failures_total) by (reason)`

---

## 安全與隱私考量

### 禁止暴露的信息
1. **敏感憑證**：密碼、授權碼、令牌完整內容
2. **PKCE 密鑰**：code_verifier, code_challenge
3. **個人身份信息**：email（除非脫敏）、真實姓名

### 推薦實踐
1. **日誌保留期限**：建議 30-90 天，符合 GDPR/CCPA 要求
2. **訪問控制**：/metrics 端點應限制僅 Prometheus 服務器 IP 可訪問（通過防火牆或 IP 白名單）
   - **實現方式**：使用環境變數 `RESTRICT_METRICS_ACCESS=true` 啟用訪問控制，`ALLOWED_METRICS_IPS` 指定允許IP列表
   - **預設行為**：Demo環境預設開放本地訪問（`127.0.0.1, localhost, ::1`）
3. **告警通知**：敏感告警應通過加密通道（如 PagerDuty, Slack 私有頻道）發送

**實現方式**：可通過環境變數 `RESTRICT_METRICS_ACCESS=true` 和 `ALLOWED_METRICS_IPS` 控制訪問權限，預設 demo 環境允許本地訪問。

---

## 總結

本設計文檔確保了 SSO 系統的可觀測性達到生產級標準，支持：
1. **實時指標監控**：通過 Prometheus 追蹤業務 KPI 與性能指標
2. **結構化日誌分析**：通過 Loki 進行日誌檢索與故障排查
3. **主動告警**：通過 Prometheus AlertManager 提前發現異常
4. **可視化展示**：通過 Grafana 儀表板直觀呈現系統健康狀態

所有設計遵循 **關注點分離** 原則：應用層只負責暴露數據，監控系統的部署與管理由外部團隊負責。
