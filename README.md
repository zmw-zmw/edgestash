# EdgeStash (Enhanced Fork)

基于 **Cloudflare Workers + R2 + KV** 的轻量多用户云盘。
**单文件部署**（`worker.js`），无需数据库、无需服务器，全部数据都在你自己的 Cloudflare 账户里。

> 本仓库是 [hhy-2021/EdgeStash](https://github.com/hhy-2021/EdgeStash)（MIT）的增强分支。
> 在上游基础上修复了多个已知 Bug 与安全问题，并新增分享 v2、配额、批量管理等能力。
> 感谢原作者的项目与所有在 issue 中反馈问题的用户。

---

## 目录

- [为什么 fork](#为什么-fork)
- [特性总览](#特性总览)
- [相对上游的修复与增强](#相对上游的修复与增强)
- [部署](#部署)
- [使用指南](#使用指南)
- [API 速查](#api-速查)
- [安全设计](#安全设计)
- [常见问题](#常见问题)
- [License](#license)

---

## 为什么 fork

上游 EdgeStash 是一个优秀的单文件 R2 云盘，但在实际使用中遇到了一些问题：
特殊字符文件名在预览/下载时 404、文件夹删不掉、删除接口误报成功、分享只能分享单个文件、
音视频预览无法拖动进度条、以及若干安全隐患（zip-slip、XSS、分享清单泄露等）。

本分支在上游代码基础上做了系统性的修复与增强，**保持单文件、零依赖、Dashboard 可直接粘贴部署**的形态不变。

## 特性总览

### 文件管理

- **多用户与强隔离**：首个注册用户自动成为管理员，管理员创建/审核用户，每个用户的文件按 `<用户名>/` 前缀在 R2 层面完全隔离
- **自由用户名**：不要求邮箱格式，字母/数字/`_ . @ -`，1-64 位，全局唯一
- **文件/文件夹**：新建文件夹（一次可建多级 `a/b/c`）、重命名（文件夹递归搬移）、删除（递归删除）
- **统一上传弹窗**：单按钮入口，文件（多选）/文件夹（保留目录结构）双 tab，先选后传、确认上传
- **文件夹整体上传**：浏览器选择文件夹后自动逐级建目录并批量上传
- **文件夹打包下载**：按文件夹一键下载 ZIP，服务端流式打包，不占 Worker 内存
- **全盘容量上限**：可配置总容量（默认 9.5 GB），超限上传返回明确的中文提示
- **在线预览**：图片 / 视频 / 音频（**支持拖动进度条**，HTTP Range 206）/ PDF / 文本代码 / JSON / Markdown / Word (.docx)

### 分享 v2

- **单文件 / 整个文件夹 / 多文件** 三种分享类型（多文件自动重名去重）
- **游客逐个下载** 或 **一键打包 ZIP** 下载，无需登录
- 分享密码、有效期（1小时/1天/1个月/永久），到期自动失效（410）
- 加密分享的文件清单在验证密码前**不下发**，防止清单泄露
- 浏览/下载次数统计，管理后台随时撤销
- 48 位长随机 token，链接不可猜测

### 管理后台

- 统计数据（总分享数、浏览量、下载量）
- 用户管理：创建用户、**一次性密码重置**（随机密码仅显示一次，服务端只存哈希）
- 分享管理：列表 + **多选批量删除**（严格校验 ID，不存在的计入失败而非静默假成功）
- 全盘容量设置

### 其他

- 深色玻璃拟态 UI，移动端自适应
- 页面响应 `no-cache`（部署后刷新即最新），API `no-store`，文件响应 `nosniff`
- 自助注册：站点无用户时始终开放（用于引导管理员）；已有用户后由 `REGISTER_ENABLED` 开关控制（默认关闭）

## 相对上游的修复与增强

### 上游已知问题修复

| 上游 Issue | 状态 |
|---|---|
| #8 文件夹删不掉 | 已修复（删除路径归一化 + 递归删除 + 禁止删根目录） |
| #6 特殊文件名（空格/逗号/`#`/`?`）预览下载报错 | 已修复（URL 按段编码 + 内联事件参数编码 + 路由双形态匹配） |
| #5 支持文件夹整体上传 | 已实现（弹窗内选择文件夹，保留目录结构） |
| #4 注册功能 + 用户名 + 管理员重置密码 | 已实现（自注册走 `REGISTER_ENABLED` 开关；重置密码一次性展示） |
| #1 / #2 UI 改版 | 已被全新 UI 取代 |

README 中提到的「管理员登录无反应」已知 Bug 也已修复。

### Bug 修复（部分）

- **删除假成功**：删除不存在的文件/文件夹现在正确返回 404
- **音视频拖动进度条**：完整实现 HTTP Range（206 Partial Content），单段 Range 精确响应，多段降级 200
- **路径编码回归**：特殊字符路径在所有 API（列表/预览/下载/打包）下均可正常工作
- **面包屑编码显示**：进入含特殊字符的文件夹不再显示 `%2F` 之类的编码串

### 安全加固

- **独立 JWT 签名密钥**（可选绑定 `JWT_SECRET`）：不再复用 `ADMIN_PASSWORD`，
  防止令牌被离线爆破后泄露管理密码；未配置时自动回退旧模式，兼容上游部署
- **JWT exp 规范化**：按 RFC 7519 使用秒级时间戳（兼容读取旧毫秒令牌）
- **登录防枚举**：统一「用户名或密码错误」提示，不暴露账号是否存在
- **zip-slip 防护**：分享创建拒绝 `..` 路径，ZIP条目名逐段清洗
- **XSS 防护**：Markdown 预览经 DOMPurify 消毒后渲染
- **Cookie 安全**：`HttpOnly` + `Secure` + `SameSite=Strict`
- **nosniff**：所有文件响应禁止 MIME 嗅探

## 部署

### 方式一：Cloudflare Dashboard 粘贴部署（推荐新手）

1. **创建 R2 存储桶**：Cloudflare 控制台 → R2 → 创建存储桶（名称随意，如 `edgestash`）
2. **创建 KV 命名空间**：Workers 和 Pages → KV → 创建命名空间（名称随意）
3. **创建 Worker**：Workers 和 Pages → 创建应用程序 → 创建 Worker（名称随意）
4. **粘贴代码**：Worker 页面 → 编辑代码 → 将本仓库 `worker.js` 全文粘贴进去 → 部署
5. **配置绑定**：Worker → 设置 → 变量和机密

   | 类型 | 变量名 | 说明 |
   |---|---|---|
   | R2 绑定 | `R2_BUCKET` | 选择第 1 步创建的桶 |
   | KV 绑定 | `KV_STORE` | 选择第 2 步创建的命名空间 |
   | Secret | `ADMIN_PASSWORD` | JWT 签名密钥回退（推荐配置独立 `JWT_SECRET`；**不会明文存储**） |
   | Secret（可选，推荐） | `JWT_SECRET` | 独立 JWT 签名密钥，任意长随机字符串 |
   | 环境变量（可选） | `REGISTER_ENABLED` | 站点已有用户后，设为 `true` 开放自助注册 |

6. **完成**：访问 `https://<worker-name>.<subdomain>.workers.dev` → 打开注册页，**第一个注册的账号自动成为管理员**（用户名密码自定）。此后注册遵循 `REGISTER_ENABLED` 开关，新用户为普通用户，由管理员在后台创建或审核
7. 可选：在 Worker → 设置 → 域和路由 绑定自定义域名

### 方式二：Wrangler 命令行

```sh
git clone <本仓库>
cd <仓库目录>

# 编辑 wrangler.toml：改成你的 R2 桶名与 KV namespace id
npx wrangler secret put ADMIN_PASSWORD
# 推荐再加一个独立签名密钥：
npx wrangler secret put JWT_SECRET

npx wrangler deploy
```

> `wrangler.toml` 中预留了 `REGISTER_ENABLED` 开关，按需修改。

## 使用指南

- **上传**：工具栏「上传」→ 弹窗中选「选择文件」或「选择文件夹」tab → 选中后确认摘要 → 开始上传
- **分享**：选中文件（或进文件夹）→「创建分享」→ 从云盘选或本地上传 → 设密码/有效期 → 生成链接；
  文件夹与多文件分享的访客页支持逐个下载或打包 ZIP
- **打包下载**：文件夹列表页的下载按钮会下载整个文件夹的 ZIP
- **管理后台**：管理员登录后右上角进入，可管理用户（含一次性密码重置）、批量删除分享、设置全盘容量

## API 速查

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | 登录（`{email, password}`），成功后种 HttpOnly Cookie |
| POST | `/api/logout` | 退出登录 |
| GET | `/api/auth/check` | 检查当前登录状态 |
| POST | `/api/register` | 注册：站点无用户时首注册即管理员；已有用户需 `REGISTER_ENABLED=true` |
| GET | `/api/files/<目录>` | 列目录 |
| POST | `/api/files/<目标目录>` | 上传文件（multipart，字段名 `file`） |
| DELETE | `/api/files/<路径>` | 删除文件/递归删除文件夹（目标不存在返回 404） |
| PUT | `/api/files/<路径>` | 重命名（文件夹递归搬移） |
| POST | `/api/folders` | 新建文件夹（支持 `a/b/c` 多级） |
| GET | `/api/download/<路径>` | 下载（支持 Range） |
| GET | `/api/preview/<路径>` | 预览（音视频支持 Range 206 拖动进度） |
| GET | `/api/download-folder/<路径>` | 整个文件夹流式打包 ZIP 下载 |
| POST | `/api/share` | 创建分享（`{type: file/folder/multi, filePath/path, password, expiresIn}`） |
| GET | `/api/share/<id>` | 游客取分享信息（加密分享不回文件清单） |
| POST | `/api/share/<id>/verify` | 验证分享密码，返回完整清单 |
| POST | `/api/share/<id>/file` | 游客下载单个文件（支持 Range） |
| POST | `/api/share/<id>/zip` | 游客打包下载（文件夹/多文件） |
| GET | `/api/admin/stats` | 统计数据（管理员） |
| GET/PUT | `/api/admin/storage` | 查看/设置全盘容量上限（管理员） |
| GET | `/api/admin/shares` | 列出所有分享（管理员） |
| DELETE | `/api/admin/shares/<id>` | 删除单个分享（管理员） |
| POST | `/api/admin/shares/batch-delete` | 批量删除分享（`{shareIds: [...]}`，管理员） |
| GET/POST/DELETE | `/api/admin/users[...]` | 用户管理（管理员） |
| POST | `/api/admin/users/<用户名>/reset-password` | 重置密码，返回一次性密码（管理员） |

## 安全设计

- 密码仅存 PBKDF2-SHA256 哈希（每密码独立随机盐，恒定时间比较）；历史版本的无盐 SHA-256 哈希会在用户下次登录时自动升级，任何人都无法查看明文密码
- JWT (HS256) 签名密钥推荐使用独立的 `JWT_SECRET`（未配置时回退 `ADMIN_PASSWORD`）
- 会话 Cookie：`HttpOnly` + `Secure` + `SameSite=Strict`
- 用户文件按 `<用户名>/` 前缀强隔离；分享记录校验 owner，游客仅能访问分享内文件
- 上传文件名去除路径分隔符；文件夹名禁止 `.` / `..` / 空段；分享与 ZIP 打包双重防 zip-slip
- 加密分享在密码验证前不下发文件清单
- Markdown 预览经 DOMPurify 消毒；全部响应带 `nosniff`；HTML `no-cache`、API `no-store`

## 常见问题

**Q：管理员是怎么产生的？**
全新部署后站点没有任何用户，此时注册页始终开放——**第一个注册的账号自动成为管理员**。之后注册需 `REGISTER_ENABLED=true`，且都只是普通用户。

**Q：忘了管理员密码怎么办？**
在 KV 中删除 `user:<管理员用户名>` 这条记录，站点即回到「无用户」状态，重新注册即可再次引导出管理员（用户名可以换新的）。

**Q：免费额度够用吗？**
Cloudflare 免费版 Workers 每天 10 万请求、R2 免费 10 GB 存储，个人/小团队使用基本够用。

**Q：和上游怎么同步？**
本分支基于上游 2026-01 版 worker.js 全面增强；上游后续更新可视情况择优合并。

## License

MIT（见 [LICENSE](LICENSE)），继承并兼容上游 [hhy-2021/EdgeStash](https://github.com/hhy-2021/EdgeStash) 的 MIT 协议。

---

* Maintained by EdgeStash Contributors
