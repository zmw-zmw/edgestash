# EdgeStash (Enhanced Fork)

基于 Cloudflare Workers + R2 + KV 的轻量多用户云盘，单文件部署，无需数据库。

> 本仓库是 [hhy2021/EdgeStash](https://github.com/hhy2021/EdgeStash)（MIT）的增强分支，
> 在上游基础上修复了多个已知 Bug，并新增多用户隔离、配额、文件夹上传等功能。
> 感谢原作者的项目与所有在 issue 中反馈问题的用户。

## 特性

- **多用户**：管理员创建用户，用户之间文件完全隔离（R2 前缀级隔离）
- **自由用户名**：用户名不要求邮箱格式，仅需唯一（支持 字母/数字/`_ . @ -`，1-64 位）
- **自助注册（可选）**：设置环境变量 `REGISTER_ENABLED=true` 后，登录页开放注册入口
- **一次性密码重置**：管理员可重置任意用户密码，生成随机密码且仅显示一次（服务端只存哈希，任何人都看不到明文）
- **用户存储配额**：按用户限制可用量，超限上传返回 413 中文提示
- **文件/文件夹**：新建文件夹（支持一次建多级）、重命名（含递归移动文件夹）、删除（递归删除整个文件夹）
- **文件夹整体上传**：浏览器选择文件夹，自动逐级建目录后批量上传
- **在线预览**：图片 / 视频 / 音频 / PDF / 文本代码 / Markdown / Word(docx)
- **分享链接**：48 位长随机 token，支持密码与有效期（1小时/1天/1个月/永久），到期自动失效（410），管理后台可随时撤销
- **UI**：深色玻璃拟态风格，移动端自适应

## 相对上游修复/改进的问题对照

| 上游 Issue | 状态 |
|---|---|
| #8 文件夹删不掉 | ✅ 已修复（删除路径归一化 + 递归删除 + 禁止删根目录） |
| #6 特殊文件名（空格/逗号等）预览报错 | ✅ 已修复（前端 URL 编码 + 内联事件参数 `encodeURIComponent`） |
| #5 支持文件夹整体上传 | ✅ 已实现 |
| #4 注册功能 + 用户名 + 管理员重置一次性密码 | ✅ 部分实现（自注册走 `REGISTER_ENABLED` 开关；重置密码一次性展示） |
| #1 / #2 UI 改版 | ✅ 已被全新 UI 取代 |
| #3 Telegram 群组作为存储后端 | ❌ 不计划（需替换存储层，超出本项目范围） |

## 部署

### 1. 前置

- 一个 Cloudflare 账号
- 创建 R2 桶（如 `edgestash`）与 KV 命名空间
- 准备一个管理密码（用于登录管理员账号与 JWT 签名，**不会明文存储**）

### 2. 绑定

Worker 需要以下绑定（见 `wrangler.toml` 示例）：

| 变量 | 类型 | 说明 |
|---|---|---|
| `R2_BUCKET` | R2 bucket | 文件存储桶 |
| `KV_STORE` | KV namespace | 用户与分享数据 |
| `ADMIN_PASSWORD` | Secret | 管理密码 / JWT 签名密钥 |
| `REGISTER_ENABLED` | 环境变量（可选） | 设为 `true` 开放自助注册，默认关闭 |

首次部署后，用用户名 `admin` + 管理密码登录即为管理员；也可手动在 KV 写入 `user:<用户名>`（`{"email":"<用户名>","passwordHash":"<SHA-256 哈希>","role":"admin"}`）自定义管理员。

### 3. 上传

```sh
npx wrangler deploy
```

或使用任意支持 module 格式 Worker 的部署方式（入口 `worker.js`，export default）。

## API 速查

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/login` | 登录（`{email, password}`），成功后种 HttpOnly Cookie |
| POST | `/api/register` | 自助注册（需 `REGISTER_ENABLED=true`） |
| GET | `/api/files/<目录>` | 列目录 |
| POST | `/api/files/<目标目录>` | 上传文件（multipart，字段名 `file`） |
| DELETE | `/api/files/<路径>` | 删除文件/递归删除文件夹 |
| PUT | `/api/files/<路径>` | 重命名（文件夹递归搬移） |
| POST | `/api/folders` | 新建文件夹（支持 `a/b/c` 多级） |
| GET | `/api/download/<路径>` | 下载 |
| GET | `/api/preview/<路径>` | 预览 |
| POST | `/api/share` | 创建分享（`{filePath, password, expiresIn}`，expiresIn: `1h/1d/1m/permanent`） |
| GET | `/api/share/<id>` | 游客取分享信息 |
| POST | `/api/share/<id>/download` | 游客下载 |
| GET/POST/PUT/DELETE | `/api/admin/users[...]` | 用户管理（管理员） |
| POST | `/api/admin/users/<用户名>/reset-password` | 重置密码（管理员，返回一次性密码） |

## 安全说明

- 密码仅存 PBKDF2 哈希，管理员也无法查看用户明文密码
- JWT (HS256) 签名密钥为 `ADMIN_PASSWORD`，HttpOnly + SameSite=Strict
- 用户文件按 `<用户名>/` 前缀强隔离，分享记录校验 owner
- 上传文件名去路径分隔符，文件夹名禁止 `.` / `..` / 空

## License

MIT（见 [LICENSE](LICENSE)），继承并兼容上游 [hhy2021/EdgeStash](https://github.com/hhy2021/EdgeStash) 的 MIT 协议。
