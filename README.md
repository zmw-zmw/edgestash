# EdgeStash Drop · 多用户网盘 + URL 抓取

> 单个 Cloudflare Worker 文件，绑定一个 KV + 一个 R2 桶即可部署的多用户云盘。
> 本仓库为 **EdgeStash** 与 **mod-mirror**（URL 抓取器）的合并升级版：抓取的文件直接进用户网盘，统一列表、统一分享、统一配额。

## 功能

**网盘（EdgeStash 内核）**

- 多用户 + 角色体系（第一个注册用户自动成为管理员；注册开关可控）
- 文件上传 / 新建文件夹 / 重命名 / 删除 / 文本与图片预览 / 文件夹打包 zip 下载
- 分享链接：可带访问密码 + 有效期（1d / 7d / 30d / 永久），支持文件 / 文件夹 / 多文件打包分享
- 每用户存储配额 + 全站存储上限，管理员后台一键管理
- 用户文件以 R2 键前缀 `<用户名>/` 强隔离，互相不可见

**URL 抓取（mod-mirror 合并）**

- 粘贴任意外部 https 直链，Cloudflare 边缘代为抓取（对 GitHub Releases / raw / npm 等尤其快）
- SSE 实时进度（250ms 心跳），抓完直接落进用户网盘的 `grab/` 目录
- 抓取文件与上传文件同等对待：可重命名、可分享、计入配额
- SSRF 防护：拒绝内网 / 链路本地 / 元数据地址（127. / 10. / 169.254. / 192.168. / 100.64. / 169.254.169.254 等），仅允许 https

**安全**

- JWT（HS256）会话，Cookie HttpOnly 传输
- 密码 PBKDF2-SHA256（每密码随机盐，10000 迭代），旧无盐哈希登录后自动升级
- 全站存储上限（默认 9.5GB，对应 R2 免费额度），管理员可调
- 页面静态资源存放于 R2 `__pages__/` 前缀，Worker 冷启动不再因内联 HTML 超预算

## 部署

### 1. 准备

- 一个 Cloudflare 账户
- 创建：KV 命名空间（账号数据）、R2 桶（文件存储）
- 本仓库 `index.js` 为部署用单文件模块（含全部 UI 与逻辑）

### 2. 绑定清单

| 类型 | 名称 | 指向 |
|---|---|---|
| KV Namespace | `KV_STORE` | 账号 / 分享 / 配置 |
| R2 Bucket | `R2_BUCKET` | 文件存储桶 |
| Secret | `JWT_SECRET` | JWT 签名密钥（随机 64 hex） |
| Secret | `ADMIN_PASSWORD` | 首次部署引导标记（站点已有用户后仅作占位） |
| Plain text | `REGISTER_ENABLED` | `true` 开放自助注册 / 其他值关闭 |

### 3. 上线

```bash
npx wrangler deploy index.js --name edgestash-drop \
  --compatibility-date 2025-08-16
```

或通过 API 以 multipart 上传（`main_module: index.js`）。部署后打开站点：**第一个注册的用户自动成为管理员**；之后在管理后台创建用户 / 调整配额 / 关闭注册。

### 4. 自定义域名

Workers → Settings → Domains 添加自定义域，或在 zone 上建 Workers Route（如 `drop.example.com/*` → 脚本）。

## API 速览

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/register` | 自助注册（首个用户自动成为管理员） |
| POST | `/api/login` | 登录（JWT Cookie） |
| GET | `/api/files/<path>` | 列目录 |
| POST | `/api/files/<path>` | 上传文件 |
| GET | `/api/download/<path>` | 下载 |
| GET | `/api/grab?url=…&folder=…` | URL 抓取（SSE 进度流） |
| POST | `/api/share` | 创建分享（`filePath` / `folderPath` / `items`） |
| POST | `/api/share/<id>/download` | 分享下载（带密码时先 verify） |
| GET/POST/PUT/DELETE | `/api/admin/…` | 管理员：用户 / 配额 / 分享 / 存储上限 |

## 环境说明

- 免费版 Worker CPU 限制约 10ms，密码哈希迭代次数与 HTML 剥离均已按此优化
- 抓取依赖上游返回 `content-length`；无长度上限 100MB（超过会提示换直链源）
- R2 免费额度 10GB/月读取 1 百万次，默认全站上限设 9.5GB 留余量

## License

[MIT](LICENSE)
