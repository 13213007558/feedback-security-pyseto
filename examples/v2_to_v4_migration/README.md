# v2.public → v4.public 迁移样例（PySETO，离线可运行）

用同一套 Ed25519 测试密钥同时产生旧版 `v2.public` 与新版 `v4.public` token，
新版通过 PASETO v4 的 **implicit assertion** 把租户（`tid`）与用途（`purpose`）
签进 Ed25519 签名输入；不连接任何真实账号服务，密钥由固定 seed 确定性生成。

## 运行

```bash
python3 demo.py            # 端到端演示 + 接受矩阵
python3 -m pytest tests/ -q  # 17 个迁移不变量测试
```

依赖：`pyseto>=1.10`、`cryptography`（测试用 `pytest`）。

## 关键事实（均由代码实测，非推断）

1. **v2 没有 implicit assertion 槽位**。PySETO 中 `V2Public.sign/verify` 的
   `implicit_assertion` 参数以下划线命名并被忽略（见 `pyseto/versions/v2.py`），
   任意 assertion 都能验签成功。因此 v2 payload 里的 `tid` 只是普通声明，
   **不构成密码学绑定**。
2. **v4 的 implicit assertion 进入签名输入**：`m2 = PAE(header, payload, footer, assertion)`
   （见 `pyseto/versions/v4.py`）。assertion 不写进 token，验签端必须重建完全一致的
   字节串，空 assertion、错误租户、错误用途都会在验签阶段直接失败。
3. **同一把 Ed25519 原始密钥在两个版本下 PASERK id 不同**（版本前缀与哈希输入不同）：
   - v2: `k2.pid.7izEIEUPy7H8...`
   - v4: `k4.pid.aFyPJn8JR0dp...`
   本样例以 PySETO 1.10.0 实际输出为准；密钥轮换/白名单应按版本分别登记 id。
4. **版本头是入口的第一道闸门**：`v2.public.` / `v4.public.` 前缀不匹配即
   `UnsupportedVersion`；把 v4 token 的头改成 v2 会因签名输入含不同 header 而验签失败。

## 接受矩阵

| 入口 \ Token | 旧 v2 token | 新 v4 token（assertion 匹配） | 新 v4 token（错误租户/用途） | 新 v4 token（签发时无 assertion） | 改版本头的 token |
|---|---|---|---|---|---|
| 旧入口 `LegacyV2Entry` | **ACCEPT**（仅签名有效，租户未绑定） | REJECT 版本 | REJECT 版本 | REJECT 版本 | REJECT（非 v2 头） |
| 新入口 `StrictV4Entry(tenant-a,billing)` | REJECT 版本 | **ACCEPT**（租户+用途强绑定） | REJECT 绑定（验签失败） | REJECT 绑定（空 assertion 验签失败） | REJECT（头/签名不一致） |

矩阵由 `demo.py` 在运行时实际计算输出，`tests/test_migration.py` 逐条固化。

### 旧入口的存续条件

- 仅接受 `v2.public.` 头且签名、`exp` 有效的 token；
- 仅在迁移窗口内保留，返回的 `Principal.token_version == "v2"`，
  其 `tid/purpose` 标注为 **UNBOUND advisory claims**；
- 旧入口永不发放新业务路由的访问权（见下）。

### 新入口的拒绝规则

- 非 `v4.public.` 头 → `UnsupportedVersion`；
- implicit assertion 缺失/为空、租户不符、用途不符 → Ed25519 验签失败 → `BindingError`；
- 验签通过但 payload 缺 `tid`/`purpose` 或与绑定值矛盾 → `BindingError`；
- `exp` 过期 → `BindingError(Token expired)`。

## “旧 token 还能验签” ≠ “获得新租户绑定”

`TestNoLoopbackToBoundRoute` 证明：旧 token 在旧入口可以反复验签成功，
但拿到的 `Principal` 永远是 `v2`，经过业务统一闸门 `guard_new_route` 时
必然抛 `RejectedByEntry`。新业务路由 `new_bound_route` 只接受
通过 v4 implicit assertion 验签的 `v4` Principal，兼容路径无法绕回。

## 切换步骤

1. **双发并行**：新 token 以 `issue_strict_v4` 签发（assertion = `tid=<租户>;purpose=<用途>`），
   旧 token 仍由 `issue_legacy_v2` 签发；两个入口并存，按版本头分流。
2. **登记 PASERK id**：验证方分别登记 `k2.pid.*` 与 `k4.pid.*`，
   不要假设同密钥 id 相同；白名单/`kid` footer 按版本校验。
3. **新业务收口**：所有要求租户绑定的路由前置 `StrictV4Entry` + `guard_new_route`，
   代码审查确认不存在接受 v2 Principal 的旁路。
4. **流量迁移与观测**：客户端切换到 v4，监控旧入口命中率与新入口的
   `BindingError` 分类（错误租户 / 缺 assertion / 过期），直到旧入口流量趋零。
5. **下线旧入口**：移除 `LegacyV2Entry` 与 v2 验签密钥登记，保留 v4 单一入口；
   下线后任何 `v2.public.` token 在所有入口均被拒绝。
6. （可选）**密钥轮换**：下线后可换用独立 v4 密钥，彻底切断与 v2 时期密钥的关系。

## 目录

- `migration_sample/keys.py` — 固定 seed 的双版本测试密钥
- `migration_sample/assertions.py` — 规范化 implicit assertion
- `migration_sample/tokens.py` — 签发函数与两个入口（含完整拒绝规则）
- `migration_sample/business.py` — 业务路由与防绕回闸门
- `demo.py` — 离线端到端演示
- `tests/test_migration.py` — 17 条不变量测试
