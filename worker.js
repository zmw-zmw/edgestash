/**
 * EdgeStash - Cloudflare-based Cloud Drive
 * 
 * A complete cloud storage solution built on Cloudflare Worker, R2, and KV.
 * 
 * Environment Variables (set in Cloudflare Dashboard):
 * - ADMIN_PASSWORD: Administrator password for login
 * 
 * Bindings (set in Cloudflare Dashboard):
 * - R2_BUCKET: R2 bucket binding for file storage
 * - KV_STORE: KV namespace binding for metadata storage
 */

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Generate a random string for IDs and tokens
 */
function generateId(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}

/**
 * Password hashing.
 * 新格式：PBKDF2-SHA256（每密码随机盐）→ "pbkdf2$<iter>$<saltB64url>$<hashB64url>"
 * 旧格式：无盐 SHA-256 hex（上游遗留），登录校验成功后自动升级为新格式
 */
const PBKDF2_ITERATIONS = 10000; // Worker CPU 友好的迭代次数（免费版 10ms 限制内）

function bytesToB64u(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64uToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}

async function pbkdf2Derive(password, saltBytes, iterations) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations },
    key, 256
  );
  return new Uint8Array(bits);
}

async function sha256Hex(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await pbkdf2Derive(password, salt, PBKDF2_ITERATIONS);
  return 'pbkdf2$' + PBKDF2_ITERATIONS + '$' + bytesToB64u(salt) + '$' + bytesToB64u(bits);
}

function timingSafeEqualStr(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

async function verifyPassword(password, stored) {
  if (typeof stored !== 'string') return false;
  if (stored.startsWith('pbkdf2$')) {
    const parts = stored.split('$');
    if (parts.length !== 4) return false;
    const iterations = parseInt(parts[1], 10);
    if (!iterations || iterations < 1 || iterations > 10000000) return false;
    try {
      const salt = b64uToBytes(parts[2]);
      const actual = bytesToB64u(await pbkdf2Derive(password, salt, iterations));
      return timingSafeEqualStr(actual, parts[3]);
    } catch (e) {
      return false;
    }
  }
  // 旧格式：无盐 SHA-256 hex
  const legacy = await sha256Hex(password);
  return timingSafeEqualStr(legacy, stored);
}

/**
 * Create a JWT token
 */
async function createJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${encodedHeader}.${encodedPayload}`)
  );
  
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

/**
 * Verify a JWT token
 */
async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signatureData = Uint8Array.from(atob(encodedSignature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      signatureData,
      encoder.encode(`${encodedHeader}.${encodedPayload}`)
    );
    
    if (!valid) return null;
    
    const payload = JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));
    
    // Check expiration（兼容旧毫秒令牌与新秒令牌，RFC 7519 要求秒）
    if (payload.exp) {
      const expMs = payload.exp > 1e12 ? payload.exp : payload.exp * 1000;
      if (Date.now() > expMs) return null;
    }
    
    return payload;
  } catch (e) {
    return null;
  }
}

/**
 * Get expiration timestamp based on duration string
 */
function getExpirationTime(expiresIn) {
  const now = Date.now();
  switch (expiresIn) {
    case '1h': return now + 60 * 60 * 1000;
    case '1d': return now + 24 * 60 * 60 * 1000;
    case '1m': return now + 30 * 24 * 60 * 60 * 1000;
    case 'permanent': return null;
    default: return now + 24 * 60 * 60 * 1000;
  }
}

/**
 * Format file size for display
 */
function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Get MIME type from file extension
 */
function getMimeType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const mimeTypes = {
    'html': 'text/html',
    'css': 'text/css',
    'js': 'application/javascript',
    'json': 'application/json',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'svg': 'image/svg+xml',
    'webp': 'image/webp',
    'ico': 'image/x-icon',
    'pdf': 'application/pdf',
    'zip': 'application/zip',
    'txt': 'text/plain',
    'md': 'text/markdown',
    'mp3': 'audio/mpeg',
    'mp4': 'video/mp4',
    'webm': 'video/webm',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

/**
 * Check if file is previewable
 */
function getPreviewType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  
  // Image files
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico', 'bmp'].includes(ext)) {
    return 'image';
  }
  
  // PDF files
  if (ext === 'pdf') {
    return 'pdf';
  }
  
  // Text/code files
  if (['txt', 'md', 'json', 'js', 'ts', 'css', 'html', 'xml', 'yaml', 'yml', 'ini', 'conf', 'sh', 'bash', 'py', 'java', 'c', 'cpp', 'h', 'hpp', 'go', 'rs', 'sql', 'log'].includes(ext)) {
    return 'text';
  }
  
  // Word documents (use Mammoth.js)
  if (ext === 'docx') {
    return 'word';
  }
  
  // Video files
  if (['mp4', 'webm', 'ogg'].includes(ext)) {
    return 'video';
  }
  
  // Audio files
  if (['mp3', 'wav', 'ogg', 'flac', 'm4a'].includes(ext)) {
    return 'audio';
  }
  
  return null;
}

/**
 * Parse cookies from request
 */
function parseCookies(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookies = {};
  cookieHeader.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });
  return cookies;
}

/**
 * Create JSON response
 */
function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...headers
    }
  });
}

/**
 * Create HTML response
 */
function htmlResponse(html, status = 200, headers = {}) {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'Referrer-Policy': 'no-referrer',
      ...headers
    }
  });
}

// ============================================================================
// AUTHENTICATION HANDLERS
// ============================================================================

async function handleLogin(request, env) {
  try {
    const body = await request.json();
    const { email, password } = body;

    if (!email || !password) {
      return jsonResponse({ success: false, message: '请输入用户名和密码' }, 400);
    }

    let userData = await env.KV_STORE.get(`user:${email}`);

    if (!userData) {
      return jsonResponse({ success: false, message: '用户名或密码错误' }, 401);
    }

    const user = JSON.parse(userData);
    const ok = await verifyPassword(password, user.passwordHash);

    if (!ok) {
      return jsonResponse({ success: false, message: '用户名或密码错误' }, 401);
    }

    // 旧格式（无盐 SHA-256）登录成功后自动升级为 PBKDF2
    if (!user.passwordHash.startsWith('pbkdf2$')) {
      user.passwordHash = await hashPassword(password);
      await env.KV_STORE.put(`user:${email}`, JSON.stringify(user));
    }

    // 按用户在 KV 中的实际角色签发 JWT（管理员用户 role:'admin' 即获得管理员权限）
    const role = user.role || 'user';
    const token = await createJWT(
      { email: user.email, role, exp: Math.floor(Date.now() / 1000) + 86400 },
      env.JWT_SECRET || env.ADMIN_PASSWORD
    );

    return jsonResponse(
      { success: true, role, email: user.email },
      200,
      { 'Set-Cookie': `token=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400` }
    );
  } catch (e) {
    return jsonResponse({ success: false, message: '登录失败: ' + e.message }, 500);
  }
}

async function handleLogout() {
  return jsonResponse(
    { success: true },
    200,
    { 'Set-Cookie': 'token=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0' }
  );
}

async function verifyAuth(request, env) {
  const cookies = parseCookies(request);
  const token = cookies.token;
  
  if (!token) return null;
  
  return await verifyJWT(token, env.JWT_SECRET || env.ADMIN_PASSWORD);
}

async function requireAuth(request, env) {
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return jsonResponse({ success: false, message: '未授权' }, 401);
  }
  return auth;
}

async function requireAdmin(request, env) {
  const auth = await verifyAuth(request, env);
  if (!auth || auth.role !== 'admin') {
    return jsonResponse({ success: false, message: '需要管理员权限' }, 403);
  }
  return auth;
}

// ============================================================================
// FILE MANAGEMENT HANDLERS
// ============================================================================

// 每个用户文件互相隔离：该用户所有 R2 key 都落在 <email>/ 前缀下
function userScope(auth) {
  return (auth && auth.email ? String(auth.email) : '_anonymous') + '/';
}

// URL 路径段是百分号编码的（中文/空格等），使用前必须解码；畸形编码时原样返回
function safeDecode(s) {
  try { return decodeURIComponent(s); } catch (e) { return s; }
}

async function handleListFiles(request, env, path) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    // Normalize path（虚拟路径 + 用户隔离前缀 = 真实 R2 key）
    const scope = userScope(auth);
    let rel = (path || '').replace(/^\/+/, '');
    if (rel && !rel.endsWith('/')) rel += '/';
    const prefix = scope + rel;
    
    const listed = await env.R2_BUCKET.list({ prefix, delimiter: '/' });
    
    const files = [];
    const folders = [];
    
    // Process folders (common prefixes)
    if (listed.delimitedPrefixes) {
      for (const folderPath of listed.delimitedPrefixes) {
        const name = folderPath.slice(prefix.length, -1);
        if (name) {
          folders.push({ name, path: '/' + folderPath.slice(scope.length, -1) });
        }
      }
    }
    
    // Process files
    if (listed.objects) {
      for (const obj of listed.objects) {
        const name = obj.key.slice(prefix.length);
        if (name && name !== '.folder' && !name.includes('/')) {
          const previewType = getPreviewType(name);
          files.push({
            name,
            path: '/' + obj.key.slice(scope.length),
            size: obj.size,
            sizeFormatted: formatFileSize(obj.size),
            lastModified: obj.uploaded.toISOString(),
            previewType
          });
        }
      }
    }
    
    return jsonResponse({ success: true, files, folders, currentPath: '/' + prefix.slice(scope.length, -1) });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取文件列表失败: ' + e.message }, 500);
  }
}

async function handleUploadFile(request, env, path) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const formData = await request.formData();
    const file = formData.get('file');
    
    if (!file) {
      return jsonResponse({ success: false, message: '没有上传文件' }, 400);
    }
    
    // 每用户存储配额检查（0 = 不限）
    const quotaBytes = await getUserQuotaBytes(env, auth.email);
    if (quotaBytes > 0) {
      const usedBytes = await getUserUsedBytes(env, auth.email);
      if (usedBytes + file.size > quotaBytes) {
        return jsonResponse({
          success: false,
          message: `存储空间不足：配额 ${formatFileSize(quotaBytes)}，已用 ${formatFileSize(usedBytes)}，本文件 ${formatFileSize(file.size)}`
        }, 413);
      }
    }
    
    // 全盘总上限检查（默认 9.5GB，对应 R2 免费额度；提示语按角色区分）
    const capBytes = await getStorageCapBytes(env);
    if (capBytes > 0) {
      const globalUsed = await getGlobalUsedBytes(env);
      if (globalUsed + file.size > capBytes) {
        const msg = auth.role === 'admin'
          ? '云盘存储已超过上限（已用 ' + formatFileSize(globalUsed) + ' / 上限 ' + formatFileSize(capBytes) + '），请在管理后台调整上限'
          : '云盘免费额度不够：已用 ' + formatFileSize(globalUsed) + ' / 上限 ' + formatFileSize(capBytes) + '，若需要调整请联系管理员';
        return jsonResponse({ success: false, message: msg }, 413);
      }
    }
    
    // Normalize path（用户前缀隔离；吞掉多余的前导斜杠）
    let filePath = (path || '').replace(/^\/+/, '');
    if (filePath && !filePath.endsWith('/')) filePath += '/';
    
    const scope = userScope(auth);
    const safeName = (file.name || 'file').split('/').pop() || 'file';
    const key = scope + filePath + safeName;
    
    await env.R2_BUCKET.put(key, file.stream(), {
      httpMetadata: { contentType: file.type || getMimeType(file.name) }
    });
    
    return jsonResponse({ success: true, message: '文件上传成功', path: '/' + key.slice(scope.length) });
  } catch (e) {
    return jsonResponse({ success: false, message: '文件上传失败: ' + e.message }, 500);
  }
}

async function handleDeleteFile(request, env, path) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    let rel = (path || '').replace(/^\/+/, '').replace(/\/+$/, '');
    if (!rel) {
      return jsonResponse({ success: false, message: '不能删除根目录' }, 400);
    }
    const key = userScope(auth) + rel;
    
    // Check if it's a folder (has objects with this prefix)
    const listed = await env.R2_BUCKET.list({ prefix: key + '/', limit: 1 });

    if (listed.objects && listed.objects.length > 0) {
      // It's a folder, delete all contents recursively
      let cursor;
      do {
        const batch = await env.R2_BUCKET.list({ prefix: key + '/', cursor });
        if (batch.objects && batch.objects.length > 0) {
          await env.R2_BUCKET.delete(batch.objects.map(obj => obj.key));
        }
        cursor = batch.truncated ? batch.cursor : null;
      } while (cursor);
    } else {
      // 不是文件夹：目标文件必须真实存在，否则 404（避免"假成功"误导调用方）
      const head = await env.R2_BUCKET.head(key);
      if (!head) {
        return jsonResponse({ success: false, message: '文件或文件夹不存在' }, 404);
      }
    }
    
    // Try to delete the file itself
    await env.R2_BUCKET.delete(key);
    
    return jsonResponse({ success: true, message: '删除成功' });
  } catch (e) {
    return jsonResponse({ success: false, message: '删除失败: ' + e.message }, 500);
  }
}

async function handleRenameFile(request, env, path) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const body = await request.json();
    const { newName } = body;
    
    if (!newName) {
      return jsonResponse({ success: false, message: '请提供新名称' }, 400);
    }
    
    if (newName.includes('/')) {
      return jsonResponse({ success: false, message: '名称不能包含 /' }, 400);
    }
    
    const scope = userScope(auth);
    let rel = (path || '').replace(/^\/+/, '');
    const oldKey = scope + rel;
    
    const parentPath = oldKey.includes('/') ? oldKey.substring(0, oldKey.lastIndexOf('/') + 1) : '';
    const newKey = parentPath + newName;
    
    // 情况一：普通文件，直接搬
    const oldObject = await env.R2_BUCKET.get(oldKey);
    if (oldObject) {
      await env.R2_BUCKET.put(newKey, oldObject.body, {
        httpMetadata: oldObject.httpMetadata
      });
      await env.R2_BUCKET.delete(oldKey);
      
      return jsonResponse({ success: true, message: '重命名成功', newPath: '/' + newKey.slice(scope.length) });
    }
    
    // 情况二：文件夹（前缀下所有对象——含 .folder 占位——整体搬到新前缀）
    const first = await env.R2_BUCKET.list({ prefix: oldKey + '/', limit: 1 });
    if (!first.objects || first.objects.length === 0) {
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }
    
    let cursor;
    do {
      const batch = await env.R2_BUCKET.list({ prefix: oldKey + '/', cursor });
      for (const obj of (batch.objects || [])) {
        const dest = newKey + '/' + obj.key.slice(oldKey.length + 1);
        const body = await env.R2_BUCKET.get(obj.key);
        if (body) {
          await env.R2_BUCKET.put(dest, body.body, { httpMetadata: body.httpMetadata });
          await env.R2_BUCKET.delete(obj.key);
        }
      }
      cursor = batch.truncated ? batch.cursor : null;
    } while (cursor);
    
    return jsonResponse({ success: true, message: '重命名成功', newPath: '/' + newKey.slice(scope.length) });
  } catch (e) {
    return jsonResponse({ success: false, message: '重命名失败: ' + e.message }, 500);
  }
}

async function handleCreateFolder(request, env) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const body = await request.json();
    let { path: folderPath } = body;
    
    if (!folderPath) {
      return jsonResponse({ success: false, message: '请提供文件夹路径' }, 400);
    }
    
    // 归一：'/' 是路径分隔符，不能作为文件夹名；按段拆分后重组
    const segs = String(folderPath).split('/').filter(Boolean);
    if (segs.length === 0) {
      return jsonResponse({ success: false, message: '文件夹名不能为空（/ 是路径分隔符，不能作为名称）' }, 400);
    }
    if (segs.some(s => s === '.' || s === '..')) {
      return jsonResponse({ success: false, message: '文件夹名不能是 . 或 ..' }, 400);
    }
    
    const cleanPath = segs.join('/') + '/';
    
    // Create an empty placeholder file to represent the folder（用户前缀隔离）
    await env.R2_BUCKET.put(userScope(auth) + cleanPath + '.folder', new Uint8Array(0));
    
    return jsonResponse({ success: true, message: '文件夹创建成功', path: '/' + segs.join('/') });
  } catch (e) {
    return jsonResponse({ success: false, message: '创建文件夹失败: ' + e.message }, 500);
  }
}

// ============================================================================
// FILE DOWNLOAD / PREVIEW（支持 Range/206，音视频可拖动进度条、部分播放器可用）
// ============================================================================

// 解析 Range 头：成功返回 {start,end}；无/非法/越界返回 null
function parseRangeHeader(header, size) {
  if (!header) return null;
  const m = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!m || (m[1] === '' && m[2] === '')) return null;
  let start, end;
  if (m[1] === '') {
    // bytes=-N：最后 N 字节
    const suffix = parseInt(m[2], 10);
    if (suffix <= 0) return null;
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = parseInt(m[1], 10);
    end = m[2] === '' ? size - 1 : Math.min(parseInt(m[2], 10), size - 1);
  }
  if (start >= size || start > end) return null;
  return { start, end };
}

// 按请求的 Range 头从 R2 取对象
async function getRangedObject(env, key, request) {
  const rangeHeader = request.headers.get('Range');
  // 多段 Range（如 bytes=0-1,5-6）不处理，降级为 200 全量返回
  if (!rangeHeader || rangeHeader.indexOf(',') >= 0) {
    const object = await env.R2_BUCKET.get(key);
    if (!object) return { object: null };
    return { object, status: 200, range: null };
  }
  const head = await env.R2_BUCKET.head(key);
  if (!head) return { object: null };
  const range = parseRangeHeader(rangeHeader, head.size);
  if (!range) return { object: null, status: 416, size: head.size };
  const object = await env.R2_BUCKET.get(key, { range: { offset: range.start, length: range.end - range.start + 1 } });
  if (!object) return { object: null };
  return { object, status: 206, range: { start: range.start, end: range.end, size: head.size } };
}

// 组装文件响应（含 Range 206 头）
function buildFileResponse(object, status, range, filename, disposition, extraHeaders) {
  const headers = {
    'Content-Type': object.httpMetadata?.contentType || getMimeType(filename),
    'Accept-Ranges': 'bytes',
    'X-Content-Type-Options': 'nosniff',
    ...(extraHeaders || {})
  };
  if (disposition) headers['Content-Disposition'] = disposition;
  if (range) {
    headers['Content-Range'] = 'bytes ' + range.start + '-' + range.end + '/' + range.size;
    headers['Content-Length'] = String(range.end - range.start + 1);
  } else {
    headers['Content-Length'] = object.size;
  }
  return new Response(object.body, { status, headers });
}

function rangeNotSatisfiable(size) {
  return new Response(null, { status: 416, headers: { 'Content-Range': 'bytes */' + size } });
}

async function handleDownloadFile(request, env, path) {
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return jsonResponse({ success: false, message: '未授权' }, 401);
  }

  try {
    let rel = (path || '').replace(/^\/+/, '');
    const key = userScope(auth) + rel;

    const { object, status, range, size } = await getRangedObject(env, key, request);
    if (!object) {
      if (status === 416) return rangeNotSatisfiable(size);
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }

    const filename = key.split('/').pop();

    return buildFileResponse(object, status, range, filename,
      'attachment; filename="' + encodeURIComponent(filename) + '"');
  } catch (e) {
    return jsonResponse({ success: false, message: '下载失败: ' + e.message }, 500);
  }
}

// Preview file handler - returns file content for inline viewing
async function handlePreviewFile(request, env, path) {
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return jsonResponse({ success: false, message: '未授权' }, 401);
  }

  try {
    let rel = (path || '').replace(/^\/+/, '');
    const key = userScope(auth) + rel;

    const { object, status, range, size } = await getRangedObject(env, key, request);
    if (!object) {
      if (status === 416) return rangeNotSatisfiable(size);
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }

    const filename = key.split('/').pop();

    return buildFileResponse(object, status, range, filename, null, {
      'Cache-Control': 'private, max-age=3600'
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '预览失败: ' + e.message }, 500);
  }
}

// ============================================================================
// SHARE HANDLERS
// ============================================================================

// ============================================================================
// SHARE HANDLERS（支持单文件 / 文件夹 / 多文件分享 + 游客逐个下载 + 打包 ZIP）
// ============================================================================

async function getShareRecord(env, shareId) {
  const raw = await env.KV_STORE.get('share:' + shareId);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

function shareExpired(share) {
  return share.expiresAt && Date.now() > share.expiresAt;
}

// 兼容 JSON / form 两种提交（游客页用 form POST + iframe 触发浏览器原生流式下载）
async function readShareCredentials(request) {
  const ct = request.headers.get('Content-Type') || '';
  try {
    if (ct.includes('application/json')) {
      const body = await request.json();
      return { password: body.password || '', path: body.path || '' };
    }
    const form = await request.formData();
    return { password: form.get('password') || '', path: form.get('path') || '' };
  } catch (e) {
    return { password: '', path: '' };
  }
}

async function checkSharePasswordWith(share, password) {
  if (!share.passwordHash) return null;
  if (!password) return jsonResponse({ success: false, message: '请输入密码' }, 401);
  const ok = await verifyPassword(password, share.passwordHash);
  if (!ok) return jsonResponse({ success: false, message: '密码错误' }, 401);
  return null;
}

// 汇总分享包含的文件清单 [{key,name,size}]（文件夹分享实时列举）
async function listShareEntries(env, share) {
  if (share.type === 'folder') {
    const entries = [];
    let cursor;
    do {
      const batch = await env.R2_BUCKET.list({ prefix: share.folderPath, cursor });
      for (const obj of (batch.objects || [])) {
        const name = obj.key.slice(share.folderPath.length);
        if (!name || name === '.folder' || name.endsWith('/.folder')) continue;
        entries.push({ key: obj.key, name, size: obj.size });
      }
      cursor = batch.truncated ? batch.cursor : null;
    } while (cursor);
    return entries;
  }
  if (share.type === 'multi') {
    return (share.items || []).map(it => ({ key: it.key, name: it.name, size: it.size }));
  }
  return [{ key: share.filePath, name: share.fileName, size: share.fileSize }];
}

async function bumpShareStats(env, share, shareId, field) {
  share[field] = (share[field] || 0) + 1;
  await env.KV_STORE.put('share:' + shareId, JSON.stringify(share));
  const statKey = field === 'viewCount' ? 'stats:totalViews' : 'stats:totalDownloads';
  const total = parseInt(await env.KV_STORE.get(statKey) || '0');
  await env.KV_STORE.put(statKey, String(total + 1));
}

async function handleCreateShare(request, env) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;

  try {
    const body = await request.json();
    const password = body.password;
    const expiresIn = body.expiresIn;
    const scope = userScope(auth);

    let shareType = body.type;
    if (!shareType && Array.isArray(body.items) && body.items.length) shareType = 'multi';
    if (!shareType) shareType = 'file';

    const shareData = {
      shareId: null,
      owner: auth.email,
      type: shareType,
      passwordHash: password ? await hashPassword(password) : null,
      expiresAt: getExpirationTime(expiresIn || '1d'),
      viewCount: 0,
      downloadCount: 0,
      createdAt: Date.now()
    };

    if (shareType === 'file') {
      if (!body.filePath) {
        return jsonResponse({ success: false, message: '请提供文件路径' }, 400);
      }
      let key = body.filePath;
      if (key.startsWith('/')) key = key.slice(1);
      key = scope + key;
      const object = await env.R2_BUCKET.head(key);
      if (!object) {
        return jsonResponse({ success: false, message: '文件不存在' }, 404);
      }
      shareData.filePath = key;
      shareData.fileName = key.split('/').pop();
      shareData.fileSize = object.size;
    } else if (shareType === 'folder') {
      if (!body.folderPath) {
        return jsonResponse({ success: false, message: '请提供文件夹路径' }, 400);
      }
      const segs = String(body.folderPath).split('/').filter(Boolean);
      if (!segs.length || segs.some(s => s === '.' || s === '..')) {
        return jsonResponse({ success: false, message: '文件夹路径无效' }, 400);
      }
      const folderKey = scope + segs.join('/') + '/';
      // 确认文件夹存在（.folder 占位 或 前缀下有对象），并统计大小
      let count = 0, total = 0, cursor;
      do {
        const batch = await env.R2_BUCKET.list({ prefix: folderKey, cursor });
        for (const obj of (batch.objects || [])) { count++; total += obj.size; }
        cursor = batch.truncated ? batch.cursor : null;
      } while (cursor);
      const hasPlaceholder = await env.R2_BUCKET.head(folderKey + '.folder');
      if (count === 0 && !hasPlaceholder) {
        return jsonResponse({ success: false, message: '文件夹不存在' }, 404);
      }
      shareData.folderPath = folderKey;
      shareData.folderName = segs[segs.length - 1];
      shareData.fileName = shareData.folderName;
      shareData.fileSize = total;
      shareData.fileCount = count;
    } else if (shareType === 'multi') {
      const list = Array.isArray(body.items) ? body.items : [];
      if (list.length === 0) {
        return jsonResponse({ success: false, message: '请提供要分享的文件' }, 400);
      }
      if (list.length > 100) {
        return jsonResponse({ success: false, message: '一次最多分享 100 个文件' }, 400);
      }
      const items = [];
      for (const p of list) {
        let key = String(p || '');
        if (key.startsWith('/')) key = key.slice(1);
        key = scope + key;
        const object = await env.R2_BUCKET.head(key);
        if (!object) {
          return jsonResponse({ success: false, message: '文件不存在: ' + String(p) }, 404);
        }
        items.push({ key, name: key.split('/').pop(), size: object.size });
      }
      // 同名 basename 去重（不同目录同名文件也能通过 /file 精确命中）
      const usedNames = {};
      let dupSeq = 0;
      for (const it of items) {
        if (usedNames[it.name]) {
          dupSeq++;
          it.name = dupSeq + '_' + it.name;
        }
        usedNames[it.name] = true;
      }
      shareData.items = items;
      shareData.fileName = items.length + ' 个文件';
      shareData.fileCount = items.length;
      shareData.fileSize = items.reduce((s, it) => s + it.size, 0);
    } else {
      return jsonResponse({ success: false, message: '未知分享类型' }, 400);
    }

    const shareId = generateId(48); // 足够长的随机 token：链接不可猜测
    shareData.shareId = shareId;
    await env.KV_STORE.put('share:' + shareId, JSON.stringify(shareData));

    // Update stats
    const totalShares = parseInt(await env.KV_STORE.get('stats:totalShares') || '0');
    await env.KV_STORE.put('stats:totalShares', String(totalShares + 1));

    return jsonResponse({
      success: true,
      shareId,
      shareUrl: '/s/' + shareId
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '创建分享链接失败: ' + e.message }, 500);
  }
}

// 分享信息 payload（带密码的分享 files 仅在验密码后返回——防清单泄露）
async function shareInfoPayload(env, share, includeFiles) {
  const entries = await listShareEntries(env, share);
  const files = entries.map(e => ({
    path: e.name,
    name: e.name.split('/').pop(),
    size: e.size,
    sizeFormatted: formatFileSize(e.size)
  }));
  return {
    success: true,
    type: share.type || 'file',
    fileName: share.fileName,
    fileSize: share.fileSize,
    fileSizeFormatted: formatFileSize(share.fileSize),
    fileCount: files.length,
    requiresPassword: !!share.passwordHash,
    expiresAt: share.expiresAt,
    files: includeFiles ? files : null
  };
}

async function handleGetShareInfo(request, env, shareId) {
  try {
    const share = await getShareRecord(env, shareId);
    if (!share) {
      return jsonResponse({ success: false, message: '分享链接不存在' }, 404);
    }

    if (shareExpired(share)) {
      return jsonResponse({ success: false, message: '分享链接已过期' }, 410);
    }

    const entries = await listShareEntries(env, share);
    const files = entries.map(e => ({
      path: e.name,
      name: e.name.split('/').pop(),
      size: e.size,
      sizeFormatted: formatFileSize(e.size)
    }));

    await bumpShareStats(env, share, shareId, 'viewCount');

    return jsonResponse({
      success: true,
      type: share.type || 'file',
      fileName: share.fileName,
      fileSize: share.fileSize,
      fileSizeFormatted: formatFileSize(share.fileSize),
      fileCount: files.length,
      requiresPassword: !!share.passwordHash,
      expiresAt: share.expiresAt
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取分享信息失败: ' + e.message }, 500);
  }
}

async function handleShareVerify(request, env, shareId) {
  try {
    const share = await getShareRecord(env, shareId);
    if (!share) {
      return jsonResponse({ success: false, message: '分享链接不存在' }, 404);
    }
    if (shareExpired(share)) {
      return jsonResponse({ success: false, message: '分享链接已过期' }, 410);
    }
    const creds = await readShareCredentials(request);
    const pwErr = await checkSharePasswordWith(share, creds.password);
    if (pwErr) return pwErr;
    return jsonResponse(await shareInfoPayload(env, share, true));
  } catch (e) {
    return jsonResponse({ success: false, message: '校验失败: ' + e.message }, 500);
  }
}

async function handleShareDownload(request, env, shareId) {
  try {
    const share = await getShareRecord(env, shareId);
    if (!share) {
      return jsonResponse({ success: false, message: '分享链接不存在' }, 404);
    }

    if (shareExpired(share)) {
      return jsonResponse({ success: false, message: '分享链接已过期' }, 410);
    }

    const creds = await readShareCredentials(request);
    const pwErr = await checkSharePasswordWith(share, creds.password);
    if (pwErr) return pwErr;

    if (share.type && share.type !== 'file') {
      return jsonResponse({ success: false, message: '该分享包含多个文件，请使用打包下载或逐个下载' }, 400);
    }

    const { object, status, range, size } = await getRangedObject(env, share.filePath, request);
    if (!object) {
      if (status === 416) return rangeNotSatisfiable(size);
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }

    await bumpShareStats(env, share, shareId, 'downloadCount');

    return buildFileResponse(object, status, range, share.fileName,
      'attachment; filename="' + encodeURIComponent(share.fileName) + '"');
  } catch (e) {
    return jsonResponse({ success: false, message: '下载失败: ' + e.message }, 500);
  }
}

// 游客下载分享内的单个文件（文件夹/多文件分享）
async function handleShareFileDownload(request, env, shareId) {
  try {
    const share = await getShareRecord(env, shareId);
    if (!share) {
      return jsonResponse({ success: false, message: '分享链接不存在' }, 404);
    }

    if (shareExpired(share)) {
      return jsonResponse({ success: false, message: '分享链接已过期' }, 410);
    }

    const creds = await readShareCredentials(request);
    const pwErr = await checkSharePasswordWith(share, creds.password);
    if (pwErr) return pwErr;

    let rel = String(creds.path || '').replace(/^\/+|\/+$/g, '');
    const segs = rel.split('/').filter(Boolean);
    if (!segs.length || segs.some(s => s === '.' || s === '..')) {
      return jsonResponse({ success: false, message: '文件路径无效' }, 400);
    }

    let key;
    if (share.type === 'folder') {
      key = share.folderPath + segs.join('/');
    } else if (share.type === 'multi') {
      const wanted = segs.join('/');
      const item = (share.items || []).find(it => it.name === wanted);
      if (!item) return jsonResponse({ success: false, message: '该文件不在此分享中' }, 404);
      key = item.key;
    } else {
      return jsonResponse({ success: false, message: '单文件分享请使用下载按钮' }, 400);
    }

    const { object, status, range, size } = await getRangedObject(env, key, request);
    if (!object) {
      if (status === 416) return rangeNotSatisfiable(size);
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }

    await bumpShareStats(env, share, shareId, 'downloadCount');

    const filename = segs[segs.length - 1];
    return buildFileResponse(object, status, range, filename,
      'attachment; filename="' + encodeURIComponent(filename) + '"');
  } catch (e) {
    return jsonResponse({ success: false, message: '下载失败: ' + e.message }, 500);
  }
}

// 游客打包下载分享内容（ZIP 流式生成）
async function handleShareZipDownload(request, env, shareId) {
  try {
    const share = await getShareRecord(env, shareId);
    if (!share) {
      return jsonResponse({ success: false, message: '分享链接不存在' }, 404);
    }

    if (shareExpired(share)) {
      return jsonResponse({ success: false, message: '分享链接已过期' }, 410);
    }

    const creds = await readShareCredentials(request);
    const pwErr = await checkSharePasswordWith(share, creds.password);
    if (pwErr) return pwErr;

    if (!share.type || share.type === 'file') {
      return jsonResponse({ success: false, message: '单文件分享无需打包' }, 400);
    }

    const entries = await listShareEntries(env, share);
    if (!entries.length) {
      return jsonResponse({ success: false, message: '分享内容为空' }, 400);
    }

    const total = entries.reduce((s, e) => s + e.size, 0);
    if (total > 3.5 * 1024 * 1024 * 1024) {
      return jsonResponse({ success: false, message: '分享内容过大（超过 3.5GB），无法打包下载' }, 400);
    }

    // 多文件重名去重
    const used = {};
    let dupSeq = 0;
    const zipEntries = entries.map(e => {
      let name = e.name;
      if (used[name]) {
        dupSeq++;
        name = dupSeq + '_' + name;
      }
      used[name] = true;
      return { key: e.key, name, size: e.size };
    });

    const rootName = share.type === 'folder' ? share.folderName : 'shared-files';
    const gen = zipEntriesGenerator(env, zipEntries, rootName);
    const stream = new ReadableStream({
      async pull(controller) {
        const { value, done } = await gen.next();
        if (done) controller.close();
        else controller.enqueue(value);
      }
    });
    return new Response(stream, {
      headers: {
        'Content-Type': 'application/zip',
        'Content-Disposition': 'attachment; filename="share.zip"; filename*=UTF-8\'\'' + encodeURIComponent(rootName) + '.zip'
      }
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '打包失败: ' + e.message }, 500);
  }
}

// ============================================================================
// ADMIN HANDLERS
// ============================================================================

async function handleListShares(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const shares = [];
    let cursor;
    
    do {
      const listed = await env.KV_STORE.list({ prefix: 'share:', cursor });
      for (const key of listed.keys) {
        const data = await env.KV_STORE.get(key.name);
        if (data) {
          const share = JSON.parse(data);
          shares.push({
            ...share,
            fileSizeFormatted: formatFileSize(share.fileSize),
            isExpired: share.expiresAt && Date.now() > share.expiresAt
          });
        }
      }
      cursor = listed.list_complete ? null : listed.cursor;
    } while (cursor);
    
    // Sort by creation date, newest first
    shares.sort((a, b) => b.createdAt - a.createdAt);
    
    return jsonResponse({ success: true, shares });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取分享列表失败: ' + e.message }, 500);
  }
}

async function handleDeleteShare(request, env, shareId) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    await env.KV_STORE.delete(`share:${shareId}`);
    
    // Update stats
    const totalShares = parseInt(await env.KV_STORE.get('stats:totalShares') || '0');
    if (totalShares > 0) {
      await env.KV_STORE.put('stats:totalShares', String(totalShares - 1));
    }
    
    return jsonResponse({ success: true, message: '分享链接已删除' });
  } catch (e) {
    return jsonResponse({ success: false, message: '删除分享链接失败: ' + e.message }, 500);
  }
}

// 管理后台统计数据（合计自 KV 计数器）
async function handleAdminStats(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;

  try {
    const [totalShares, totalViews, totalDownloads] = await Promise.all([
      env.KV_STORE.get('stats:totalShares'),
      env.KV_STORE.get('stats:totalViews'),
      env.KV_STORE.get('stats:totalDownloads')
    ]);
    return jsonResponse({
      success: true,
      stats: {
        totalShares: parseInt(totalShares || '0'),
        totalViews: parseInt(totalViews || '0'),
        totalDownloads: parseInt(totalDownloads || '0')
      }
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取统计失败: ' + e.message }, 500);
  }
}

async function handleBatchDeleteShares(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;

  try {
    const body = await request.json().catch(() => null);
    const ids = body && Array.isArray(body.shareIds) ? body.shareIds : null;
    if (!ids || ids.length === 0) {
      return jsonResponse({ success: false, message: 'shareIds 不能为空' }, 400);
    }
    if (ids.length > 500) {
      return jsonResponse({ success: false, message: '单次最多删除 500 条' }, 400);
    }
    // shareId 由 generateId 生成（48 位字母数字），严格校验防 KV key 注入
    const valid = ids.filter(id => typeof id === 'string' && /^[A-Za-z0-9]{8,64}$/.test(id));
    if (valid.length !== ids.length) {
      return jsonResponse({ success: false, message: '存在非法的分享 ID' }, 400);
    }

    let deleted = 0;
    const failed = [];
    for (const id of valid) {
      try {
        // 先确认存在再删，不存在的计入 failed 而非静默成功
        const data = await env.KV_STORE.get(`share:${id}`);
        if (data === null) { failed.push(id); continue; }
        await env.KV_STORE.delete(`share:${id}`);
        deleted++;
      } catch (e) {
        failed.push(id);
      }
    }

    if (deleted > 0) {
      const totalShares = parseInt(await env.KV_STORE.get('stats:totalShares') || '0');
      await env.KV_STORE.put('stats:totalShares', String(Math.max(0, totalShares - deleted)));
    }

    return jsonResponse({
      success: true,
      deleted,
      failed,
      message: failed.length ? `已删除 ${deleted} 条，${failed.length} 条失败或不存在` : `已删除 ${deleted} 条分享链接`
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '批量删除失败: ' + e.message }, 500);
  }
}

// 汇总某用户前缀下所有对象的大小（分页）
// ============ 文件夹打包下载（流式 ZIP，不落盘不占内存）============
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32Init() { return 0xFFFFFFFF; }
function crc32Push(crc, buf) {
  for (let i = 0; i < buf.length; i++) crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ buf[i]) & 0xFF];
  return crc;
}
function crc32Final(crc) { return (crc ^ 0xFFFFFFFF) >>> 0; }

function dosDateTime(ms) {
  const d = new Date(ms);
  const year = Math.max(1980, d.getUTCFullYear());
  const date = ((year - 1980) << 9) | ((d.getUTCMonth() + 1) << 5) | d.getUTCDate();
  const time = (d.getUTCHours() << 11) | (d.getUTCMinutes() << 5) | (d.getUTCSeconds() >> 1);
  return { date: date & 0xffff, time: time & 0xffff };
}

// 已经压缩过的扩展名直接 store，其余 deflate-raw
const STORE_EXTS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp', 'mp4', 'webm', 'mkv', 'mov', 'mp3', 'wav', 'flac', 'm4a', 'ogg', 'zip', 'rar', '7z', 'gz', 'bz2', 'xz', 'pdf', 'docx', 'pptx', 'xlsx'];

// 列出某前缀下所有文件（供 ZIP 打包）
async function listPrefixEntries(env, folderKey) {
  const entries = [];
  let cursor;
  do {
    const batch = await env.R2_BUCKET.list({ prefix: folderKey, cursor });
    for (const obj of (batch.objects || [])) {
      const name = obj.key.slice(folderKey.length);
      if (!name || name === '.folder' || name.endsWith('/.folder')) continue;
      entries.push({ key: obj.key, name, size: obj.size, uploaded: obj.uploaded });
    }
    cursor = batch.truncated ? batch.cursor : null;
  } while (cursor);
  return entries;
}

async function* zipEntriesGenerator(env, entries, rootName) {
  let canDeflate = false;
  try { canDeflate = typeof CompressionStream !== 'undefined' && !!new CompressionStream('deflate-raw'); } catch (e) { canDeflate = false; }

  const enc = new TextEncoder();
  const central = [];
  let offset = 0;

  const u16 = v => new Uint8Array([v & 0xff, (v >> 8) & 0xff]);
  const u32 = v => new Uint8Array([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff]);

  for (const entry of entries) {
    // 防 zip-slip：条目名按段清洗（剥掉 ..、.、空段）
    const safeName = entry.name.split('/').filter(seg => seg && seg !== '.' && seg !== '..').join('/');
    if (!safeName) continue;
    const nameBytes = enc.encode(rootName + '/' + safeName);
    const uploadedMs = entry.uploaded ? entry.uploaded.getTime() : Date.now();
    const { date, time } = dosDateTime(uploadedMs);
    const ext = safeName.split('.').pop().toLowerCase();
    const method = (canDeflate && !STORE_EXTS.includes(ext) && entry.size > 0) ? 8 : 0;

    // 先取对象再写 LFH：对象中途消失时整条跳过，不产生有头无数据的坏档
    const obj = await env.R2_BUCKET.get(entry.key);
    if (!obj) continue;

    // local file header（bit3 数据描述符模式：crc/size 先置 0，流结束后补写）
    const entryOffset = offset;
    const lfh = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(lfh.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x0808, true);
    lv.setUint16(8, method, true);
    lv.setUint16(10, time, true);
    lv.setUint16(12, date, true);
    lv.setUint16(26, nameBytes.length, true);
    lfh.set(nameBytes, 30);
    yield lfh;
    offset += lfh.length;

    let crc = crc32Init();
    let usize = 0, csize = 0;
    let stream = obj.body.pipeThrough(new TransformStream({
      transform(chunk, ctl) {
        crc = crc32Push(crc, chunk);
        usize += chunk.byteLength;
        ctl.enqueue(chunk);
      }
    }));
    const counter = new TransformStream({
      transform(chunk, ctl) { csize += chunk.byteLength; ctl.enqueue(chunk); }
    });
    stream = method === 8
      ? stream.pipeThrough(new CompressionStream('deflate-raw')).pipeThrough(counter)
      : stream.pipeThrough(counter);

    const reader = stream.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      yield value;
      offset += value.byteLength;
    }
    const finalCrc = crc32Final(crc);

    const dd = new Uint8Array(16);
    const dv = new DataView(dd.buffer);
    dv.setUint32(0, 0x08074b50, true);
    dv.setUint32(4, finalCrc, true);
    dv.setUint32(8, csize, true);
    dv.setUint32(12, usize, true);
    yield dd;
    offset += dd.length;

    central.push({ nameBytes, crc: finalCrc, csize, usize, method, date, time, offset: entryOffset });
  }

  const cdStart = offset;
  for (const c of central) {
    const cd = new Uint8Array(46 + c.nameBytes.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0808, true);
    cv.setUint16(10, c.method, true);
    cv.setUint16(12, c.time, true);
    cv.setUint16(14, c.date, true);
    cv.setUint32(16, c.crc, true);
    cv.setUint32(20, c.csize, true);
    cv.setUint32(24, c.usize, true);
    cv.setUint16(28, c.nameBytes.length, true);
    cv.setUint32(42, c.offset, true);
    cd.set(c.nameBytes, 46);
    yield cd;
    offset += cd.length;
  }

  const cdSize = offset - cdStart;
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, central.length, true);
  ev.setUint16(10, central.length, true);
  ev.setUint32(12, cdSize, true);
  ev.setUint32(16, cdStart, true);
  yield eocd;
}

async function* zipFolderGenerator(env, folderKey, folderName) {
  const entries = await listPrefixEntries(env, folderKey);
  yield* zipEntriesGenerator(env, entries, folderName);
}

async function handleDownloadFolder(request, env, path) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  try {
    const rel = (path || '').replace(/^\/+|\/+$/g, '');
    if (!rel) {
      return jsonResponse({ success: false, message: '缺少文件夹路径' }, 400);
    }
    const folderKey = userScope(auth) + rel + '/';
    let total = 0, count = 0, cursor;
    do {
      const batch = await env.R2_BUCKET.list({ prefix: folderKey, cursor });
      for (const obj of (batch.objects || [])) { total += obj.size; count++; }
      cursor = batch.truncated ? batch.cursor : null;
    } while (cursor);
    if (count === 0) {
      return jsonResponse({ success: false, message: '文件夹为空' }, 400);
    }
    if (total > 3.5 * 1024 * 1024 * 1024) {
      return jsonResponse({ success: false, message: '文件夹过大（超过 3.5GB），请分批下载' }, 400);
    }
    const folderName = rel.split('/').pop();
    const gen = zipFolderGenerator(env, folderKey, folderName);
    const stream = new ReadableStream({
      async pull(controller) {
        const { value, done } = await gen.next();
        if (done) controller.close();
        else controller.enqueue(value);
      }
    });
    return new Response(stream, {
      headers: {
        'Content-Type': 'application/zip',
        'Content-Disposition': 'attachment; filename="folder.zip"; filename*=UTF-8\'\'' + encodeURIComponent(folderName) + '.zip'
      }
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '打包失败: ' + e.message }, 500);
  }
}

async function getUserUsedBytes(env, email) {
  const prefix = (email || '_anonymous') + '/';
  let total = 0;
  let cursor;
  do {
    const batch = await env.R2_BUCKET.list({ prefix, cursor });
    for (const obj of (batch.objects || [])) total += obj.size;
    cursor = batch.truncated ? batch.cursor : null;
  } while (cursor);
  return total;
}

// 读某用户存储配额（bytes），0 = 不限
async function getUserQuotaBytes(env, email) {
  const data = await env.KV_STORE.get(`user:${email}`);
  if (!data) return 0;
  try {
    const user = JSON.parse(data);
    return Number(user.quotaBytes) > 0 ? Math.round(Number(user.quotaBytes)) : 0;
  } catch (e) {
    return 0;
  }
}

// ============ 全盘存储上限（默认 9.5GB，对应 R2 免费额度）============
const DEFAULT_STORAGE_CAP = 10200547328; // 9.5 GB

async function getStorageCapBytes(env) {
  const v = await env.KV_STORE.get('config:storageCap');
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.round(n) : DEFAULT_STORAGE_CAP;
}

async function getGlobalUsedBytes(env) {
  let total = 0;
  let cursor;
  do {
    const batch = await env.R2_BUCKET.list({ cursor });
    for (const obj of (batch.objects || [])) total += obj.size;
    cursor = batch.truncated ? batch.cursor : null;
  } while (cursor);
  return total;
}

async function handleGetStorage(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  try {
    const capBytes = await getStorageCapBytes(env);
    const usedBytes = await getGlobalUsedBytes(env);
    return jsonResponse({
      success: true,
      capBytes,
      usedBytes,
      usedFormatted: formatFileSize(usedBytes),
      capFormatted: formatFileSize(capBytes)
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取存储信息失败: ' + e.message }, 500);
  }
}

async function handleUpdateStorage(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  try {
    const body = await request.json();
    const cap = Math.round(Number(body.capBytes));
    if (!Number.isFinite(cap) || cap <= 0) {
      return jsonResponse({ success: false, message: '上限必须为正数（字节）' }, 400);
    }
    await env.KV_STORE.put('config:storageCap', String(cap));
    return jsonResponse({ success: true, message: '存储上限已更新', capBytes: cap });
  } catch (e) {
    return jsonResponse({ success: false, message: '更新失败: ' + e.message }, 500);
  }
}

// 管理员：修改某用户存储配额
async function handleUpdateUser(request, env, emailParam) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const email = decodeURIComponent(emailParam);
    const data = await env.KV_STORE.get(`user:${email}`);
    if (!data) {
      return jsonResponse({ success: false, message: '用户不存在' }, 404);
    }
    
    const body = await request.json();
    const quota = Number(body.quotaBytes) > 0 ? Math.round(Number(body.quotaBytes)) : 0;
    
    const user = JSON.parse(data);
    user.quotaBytes = quota;
    await env.KV_STORE.put(`user:${email}`, JSON.stringify(user));
    
    return jsonResponse({ success: true, message: '配额已更新', quotaBytes: quota });
  } catch (e) {
    return jsonResponse({ success: false, message: '更新配额失败: ' + e.message }, 500);
  }
}

async function handleListUsers(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const users = [];
    let cursor;
    
    do {
      const listed = await env.KV_STORE.list({ prefix: 'user:', cursor });
      for (const key of listed.keys) {
        const data = await env.KV_STORE.get(key.name);
        if (data) {
          const user = JSON.parse(data);
          const usedBytes = await getUserUsedBytes(env, user.email);
          users.push({
            email: user.email,
            role: user.role,
            createdAt: user.createdAt,
            quotaBytes: user.quotaBytes || 0,
            usedBytes,
            usedFormatted: formatFileSize(usedBytes),
            quotaFormatted: user.quotaBytes > 0 ? formatFileSize(user.quotaBytes) : '不限'
          });
        }
      }
      cursor = listed.list_complete ? null : listed.cursor;
    } while (cursor);
    
    return jsonResponse({ success: true, users });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取用户列表失败: ' + e.message }, 500);
  }
}

async function handleCreateUser(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const body = await request.json();
    const { email, password, quotaBytes } = body;
    const uname = typeof email === 'string' ? email.trim() : '';

    if (!uname || !password) {
      return jsonResponse({ success: false, message: '请提供用户名和密码' }, 400);
    }

    // 用户名合法性：仅字母/数字/_ . @ -，长度 1-64（保证 R2 键安全）
    if (!/^[A-Za-z0-9_.@-]{1,64}$/.test(uname)) {
      return jsonResponse({ success: false, message: '用户名只能包含字母、数字、_ . @ -，长度 1-64，且不能含空格和斜杠' }, 400);
    }

    // Check if user already exists
    const existing = await env.KV_STORE.get(`user:${uname}`);
    if (existing) {
      return jsonResponse({ success: false, message: '用户名已被占用' }, 409);
    }
    
    const userData = {
      email: uname,
      passwordHash: await hashPassword(password),
      role: 'user',
      quotaBytes: Number(quotaBytes) > 0 ? Math.round(Number(quotaBytes)) : 0, // 0 = 不限
      createdAt: Date.now()
    };
    
    await env.KV_STORE.put(`user:${uname}`, JSON.stringify(userData));
    
    return jsonResponse({ success: true, message: '用户创建成功', email: uname });
  } catch (e) {
    return jsonResponse({ success: false, message: '创建用户失败: ' + e.message }, 500);
  }
}

// ============ 自助注册（env.REGISTER_ENABLED === 'true' 开启）============
async function handleRegister(request, env) {
  try {
    // 首次部署引导：站点还没有任何用户时，第一个注册的人自动成为管理员（用户名/密码自定）。
    // 站点已有用户后，注册遵循 REGISTER_ENABLED 开关。
    //
    // KV 是最终一致的：首个用户写入后短时间内 list() 仍返回空，会导致连续注册出多个管理员。
    // 因此用 R2（强一致）做引导标记兜底：标记键绑定部署的 ADMIN_PASSWORD 哈希，防跨部署串扰。
    let markerKey = null;
    let siteHasUsers = (await env.KV_STORE.list({ prefix: 'user:', limit: 1 })).keys.length > 0;
    if (!siteHasUsers) {
      markerKey = 'config:bootstrap:' + (await sha256Hex(env.ADMIN_PASSWORD || ''));
      if (await env.R2_BUCKET.head(markerKey)) {
        siteHasUsers = true; // 已引导过（其他写入节点尚未在 KV 可见）
      }
    }
    if (siteHasUsers && env.REGISTER_ENABLED !== 'true') {
      return jsonResponse({ success: false, message: '本站未开放注册' }, 403);
    }

    const body = await request.json();
    const uname = typeof body.username === 'string' ? body.username.trim() : '';
    const { password } = body;

    if (!uname || !password) {
      return jsonResponse({ success: false, message: '请提供用户名和密码' }, 400);
    }
    if (!/^[A-Za-z0-9_.@-]{1,64}$/.test(uname)) {
      return jsonResponse({ success: false, message: '用户名只能包含字母、数字、_ . @ -，长度 1-64' }, 400);
    }
    if (String(password).length < 6) {
      return jsonResponse({ success: false, message: '密码至少 6 位' }, 400);
    }

    const existing = await env.KV_STORE.get(`user:${uname}`);
    if (existing) {
      return jsonResponse({ success: false, message: '用户名已被占用' }, 409);
    }

    const userData = {
      email: uname,
      passwordHash: await hashPassword(password),
      role: siteHasUsers ? 'user' : 'admin',
      quotaBytes: 0,
      createdAt: Date.now()
    };
    await env.KV_STORE.put(`user:${uname}`, JSON.stringify(userData));
    // 首个管理员落地后立刻写 R2 强一致标记，封死后续注册的引导窗口
    if (userData.role === 'admin' && markerKey) {
      await env.R2_BUCKET.put(markerKey, 'first-admin');
    }
    return jsonResponse({ success: true, message: userData.role === 'admin' ? '注册成功，你已自动成为本站管理员，请登录' : '注册成功，请登录' });
  } catch (e) {
    return jsonResponse({ success: false, message: '注册失败: ' + e.message }, 500);
  }
}

// 管理员重置用户密码：随机密码明文仅在本次响应返回，服务端只存哈希
async function handleResetUserPassword(request, env, email) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  try {
    const uname = decodeURIComponent(email);
    const raw = await env.KV_STORE.get(`user:${uname}`);
    if (!raw) {
      return jsonResponse({ success: false, message: '用户不存在' }, 404);
    }
    const user = JSON.parse(raw);
    const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
    const arr = new Uint8Array(12);
    crypto.getRandomValues(arr);
    const newPw = Array.from(arr, b => charset[b % charset.length]).join('');
    user.passwordHash = await hashPassword(newPw);
    await env.KV_STORE.put(`user:${uname}`, JSON.stringify(user));
    return jsonResponse({ success: true, message: '密码已重置', oneTimePassword: newPw });
  } catch (e) {
    return jsonResponse({ success: false, message: '重置失败: ' + e.message }, 500);
  }
}

async function handleDeleteUser(request, env, email) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const decodedEmail = decodeURIComponent(email);
    await env.KV_STORE.delete(`user:${decodedEmail}`);
    
    return jsonResponse({ success: true, message: '用户已删除' });
  } catch (e) {
    return jsonResponse({ success: false, message: '删除用户失败: ' + e.message }, 500);
  }
}

async function handleCheckAuth(request, env) {
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return jsonResponse({ authenticated: false });
  }
  return jsonResponse({ authenticated: true, role: auth.role, email: auth.email });
}

// ============================================================================
// HTML PAGES
// ============================================================================

const CSS_STYLES = `
<style>
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  :root {
    --primary: #818cf8;
    --primary-dark: #6366f1;
    --primary-light: #a5b4fc;
    --secondary: #a78bfa;
    --accent: #22d3ee;
    --background: #0a0e1a;
    --surface: rgba(255, 255, 255, 0.045);
    --surface-light: rgba(255, 255, 255, 0.09);
    --border: rgba(255, 255, 255, 0.09);
    --border-strong: rgba(255, 255, 255, 0.16);
    --text: #eef2ff;
    --text-muted: #8b93b0;
    --success: #34d399;
    --warning: #fbbf24;
    --error: #f87171;
    --gradient: linear-gradient(135deg, #6366f1 0%, #8b5cf6 55%, #22d3ee 100%);
    --radius: 14px;
    --shadow-lg: 0 18px 50px -12px rgba(0, 0, 0, 0.55);
    --glow: 0 8px 28px -6px rgba(99, 102, 241, 0.5);
  }

  html { scroll-behavior: smooth; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
    background:
      radial-gradient(1100px 700px at 12% -8%, rgba(99, 102, 241, 0.20), transparent 60%),
      radial-gradient(900px 650px at 108% 12%, rgba(34, 211, 238, 0.13), transparent 55%),
      radial-gradient(1000px 700px at 50% 115%, rgba(139, 92, 246, 0.13), transparent 60%),
      var(--background);
    background-attachment: fixed;
    color: var(--text);
    min-height: 100vh;
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
  }

  ::selection { background: rgba(99, 102, 241, 0.4); }

  ::-webkit-scrollbar { width: 10px; height: 10px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.12);
    border-radius: 8px;
    border: 2px solid transparent;
    background-clip: content-box;
  }
  ::-webkit-scrollbar-thumb:hover {
    background: rgba(255, 255, 255, 0.24);
    border: 2px solid transparent;
    background-clip: content-box;
  }

  a { color: var(--primary-light); text-decoration: none; }

  .container {
    max-width: 1180px;
    margin: 0 auto;
    padding: 24px 20px 60px;
  }

  /* ========== Header ========== */
  .header {
    position: sticky;
    top: 0;
    z-index: 100;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 28px;
    background: rgba(10, 14, 26, 0.72);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border-bottom: 1px solid var(--border);
  }

  .header::after {
    content: '';
    position: absolute;
    left: 0;
    right: 0;
    bottom: -1px;
    height: 1px;
    background: linear-gradient(90deg, transparent 5%, rgba(129, 140, 248, 0.55), rgba(34, 211, 238, 0.4), transparent 95%);
    pointer-events: none;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 9px;
    font-size: 20px;
    font-weight: 800;
    letter-spacing: 0.5px;
    background: var(--gradient);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    color: transparent;
  }

  .logo::before {
    content: '';
    width: 13px;
    height: 13px;
    border-radius: 4px;
    background: conic-gradient(from 210deg, #6366f1, #8b5cf6, #22d3ee, #6366f1);
    box-shadow: 0 0 14px rgba(99, 102, 241, 0.8);
  }

  .header-actions { display: flex; gap: 10px; }

  .user-chip {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 7px 15px;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.06);
    border: 1px solid rgba(255, 255, 255, 0.12);
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
    max-width: 220px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .user-chip::before {
    content: '';
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--gradient);
    box-shadow: 0 0 8px rgba(99, 102, 241, 0.8);
    flex-shrink: 0;
  }

  /* ========== Buttons ========== */
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 7px;
    padding: 10px 18px;
    border: 1px solid transparent;
    border-radius: 11px;
    font-size: 14px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    text-decoration: none;
    white-space: nowrap;
    transition: transform 0.16s ease, box-shadow 0.16s ease, background 0.16s ease, border-color 0.16s ease, filter 0.16s ease;
  }

  .btn:active { transform: translateY(0) scale(0.97); }

  .btn-primary {
    background: linear-gradient(135deg, #6d7cff 0%, #9d5cff 55%, #2dd4ff 100%);
    color: #fff;
    box-shadow: 0 4px 16px -4px rgba(109, 124, 255, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.28);
  }
  .btn-primary:hover {
    transform: translateY(-1px);
    box-shadow: 0 10px 26px -6px rgba(109, 124, 255, 0.65), inset 0 1px 0 rgba(255, 255, 255, 0.28);
    filter: brightness(1.06);
  }

  .btn-secondary {
    background: rgba(255, 255, 255, 0.06);
    color: var(--text);
    border-color: rgba(255, 255, 255, 0.12);
    backdrop-filter: blur(8px);
  }
  .btn-secondary:hover {
    background: rgba(255, 255, 255, 0.11);
    border-color: rgba(129, 140, 248, 0.5);
    color: #fff;
    transform: translateY(-1px);
  }

  .btn-danger {
    background: rgba(248, 113, 113, 0.10);
    color: var(--error);
    border-color: rgba(248, 113, 113, 0.28);
  }
  .btn-danger:hover {
    background: rgba(248, 113, 113, 0.20);
    border-color: rgba(248, 113, 113, 0.5);
    transform: translateY(-1px);
  }

  .btn-sm {
    padding: 5px 11px;
    font-size: 12px;
    font-weight: 500;
    border-radius: 8px;
  }

  /* ========== Forms ========== */
  .form-group { margin-bottom: 18px; }

  .form-label {
    display: block;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-muted);
    margin-bottom: 7px;
    letter-spacing: 0.3px;
  }

  .form-input,
  .form-select {
    width: 100%;
    padding: 12px 14px;
    font-size: 14px;
    font-family: inherit;
    color: var(--text);
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border);
    border-radius: 11px;
    outline: none;
    transition: border-color 0.16s ease, box-shadow 0.16s ease, background 0.16s ease;
  }

  .form-input::placeholder { color: rgba(139, 147, 176, 0.55); }

  .form-input:focus,
  .form-select:focus {
    border-color: var(--primary);
    background: rgba(99, 102, 241, 0.07);
    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.18);
  }

  .form-select { cursor: pointer; }
  .form-select option { background: #141a2e; color: var(--text); }

  /* ========== Login ========== */
  .login-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    position: relative;
    overflow: hidden;
  }

  .login-container::before,
  .login-container::after {
    content: '';
    position: absolute;
    border-radius: 50%;
    filter: blur(90px);
    pointer-events: none;
  }

  .login-container::before {
    width: 480px;
    height: 480px;
    background: rgba(99, 102, 241, 0.26);
    top: -140px;
    left: -120px;
    animation: float 9s ease-in-out infinite alternate;
  }

  .login-container::after {
    width: 420px;
    height: 420px;
    background: rgba(34, 211, 238, 0.18);
    bottom: -130px;
    right: -110px;
    animation: float 11s ease-in-out infinite alternate-reverse;
  }

  .login-card {
    position: relative;
    z-index: 1;
    width: min(410px, 100%);
    background: rgba(17, 23, 42, 0.78);
    border: 1px solid var(--border-strong);
    border-radius: 22px;
    padding: 42px 36px;
    box-shadow: var(--shadow-lg);
    backdrop-filter: blur(22px);
    -webkit-backdrop-filter: blur(22px);
    animation: fadeUp 0.5s ease;
  }

  .login-header { text-align: center; margin-bottom: 30px; }

  .login-logo {
    font-size: 32px;
    font-weight: 800;
    letter-spacing: 0.5px;
    background: var(--gradient);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    color: transparent;
  }

  .login-subtitle {
    color: var(--text-muted);
    font-size: 14px;
    margin-top: 6px;
  }

  /* ========== Breadcrumb / Toolbar / Card ========== */
  .breadcrumb {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 4px;
    padding: 9px 14px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border);
    border-radius: 11px;
    font-size: 13.5px;
    backdrop-filter: blur(10px);
  }

  .breadcrumb-item { color: var(--text-muted); transition: color 0.15s; cursor: pointer; }
  a.breadcrumb-item:hover { color: var(--primary-light); }
  .breadcrumb-item.active { color: var(--text); font-weight: 600; }
  .breadcrumb-separator { color: rgba(139, 147, 176, 0.4); margin: 0 4px; user-select: none; }

  .page-topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 20px;
  }

  .toolbar {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
  }

  .file-panel { min-height: 220px; }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 20px;
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    animation: fadeUp 0.35s ease;
  }

  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    margin-bottom: 16px;
  }

  .card-title { font-size: 16px; font-weight: 700; }

  /* ========== File Grid ========== */
  .file-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
    gap: 14px;
  }

  .file-item {
    display: flex;
    flex-direction: column;
    gap: 11px;
    padding: 18px;
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid var(--border);
    border-radius: 16px;
    cursor: pointer;
    animation: fadeUp 0.3s ease both;
    transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
  }

  .file-item:hover {
    transform: translateY(-4px);
    border-color: rgba(129, 140, 248, 0.55);
    background: rgba(255, 255, 255, 0.07);
    box-shadow: 0 18px 40px -16px rgba(99, 102, 241, 0.45);
  }

  .file-icon {
    width: 52px;
    height: 52px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 26px;
    border-radius: 15px;
    background: linear-gradient(135deg, rgba(109, 124, 255, 0.22), rgba(45, 212, 255, 0.12));
    border: 1px solid rgba(129, 140, 248, 0.3);
    box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.12);
  }

  .file-name {
    font-size: 14.5px;
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .file-meta {
    font-size: 12px;
    color: var(--text-muted);
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .file-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: auto;
    padding-top: 6px;
  }

  /* ========== Empty State ========== */
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 14px;
    padding: 70px 20px;
    color: var(--text-muted);
  }

  .empty-icon {
    width: 88px;
    height: 88px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 42px;
    border-radius: 50%;
    background: radial-gradient(circle at 30% 30%, rgba(99, 102, 241, 0.25), rgba(34, 211, 238, 0.10));
    border: 1px solid var(--border-strong);
  }

  /* ========== Badges ========== */
  .badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }
  .badge-info { background: rgba(34, 211, 238, 0.12); color: var(--accent); border: 1px solid rgba(34, 211, 238, 0.25); }
  .badge-success { background: rgba(52, 211, 153, 0.12); color: var(--success); border: 1px solid rgba(52, 211, 153, 0.25); }
  .badge-warning { background: rgba(251, 191, 36, 0.12); color: var(--warning); border: 1px solid rgba(251, 191, 36, 0.25); }
  .badge-error { background: rgba(248, 113, 113, 0.12); color: var(--error); border: 1px solid rgba(248, 113, 113, 0.25); }

  /* ========== Tabs (admin) ========== */
  .tabs {
    display: flex;
    gap: 6px;
    padding: 5px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 999px;
    width: fit-content;
    margin-bottom: 22px;
    backdrop-filter: blur(10px);
  }

  .tab {
    padding: 9px 20px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-size: 14px;
    font-weight: 600;
    font-family: inherit;
    border-radius: 999px;
    cursor: pointer;
    transition: all 0.18s ease;
  }

  .tab:hover { color: var(--text); }

  .tab.active {
    background: var(--gradient);
    color: #fff;
    box-shadow: 0 4px 14px -4px rgba(99, 102, 241, 0.5);
  }

  .tab-content { display: none; }
  .tab-content.active { display: block; animation: fadeUp 0.3s ease; }

  /* ========== Stats ========== */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 16px;
  }

  .stat-card {
    position: relative;
    overflow: hidden;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 26px 24px;
    backdrop-filter: blur(14px);
    transition: transform 0.18s ease, border-color 0.18s ease;
  }

  .stat-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: var(--gradient);
    opacity: 0.8;
  }

  .stat-card:hover { transform: translateY(-3px); border-color: rgba(99, 102, 241, 0.4); }

  .stat-value {
    font-size: 34px;
    font-weight: 800;
    line-height: 1.2;
    background: var(--gradient);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    color: transparent;
  }

  .stat-label {
    color: var(--text-muted);
    font-size: 13px;
    margin-top: 6px;
  }

  /* ========== Table ========== */
  .table-container {
    overflow-x: auto;
    border-radius: 12px;
    border: 1px solid var(--border);
  }

  .table-container table {
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }

  .table-container th {
    text-align: left;
    padding: 12px 16px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--text-muted);
    background: rgba(255, 255, 255, 0.03);
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }

  .table-container td {
    padding: 13px 16px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  }

  .table-container tbody tr { transition: background 0.15s; }
  .table-container tbody tr:hover { background: rgba(99, 102, 241, 0.06); }
  .table-container tbody tr:last-child td { border-bottom: none; }

  /* ========== Modals ========== */
  .modal-overlay {
    position: fixed;
    inset: 0;
    z-index: 900;
    display: none;
    align-items: center;
    justify-content: center;
    padding: 20px;
    background: rgba(5, 8, 18, 0.65);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
  }

  .modal-overlay.active { display: flex; animation: fadeIn 0.18s ease; }

  .modal {
    width: min(440px, 100%);
    background: rgba(20, 26, 46, 0.94);
    border: 1px solid var(--border-strong);
    border-radius: 18px;
    padding: 26px;
    box-shadow: var(--shadow-lg);
    animation: popIn 0.22s cubic-bezier(0.34, 1.56, 0.64, 1);
  }

  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 18px;
  }

  .modal-title { font-size: 17px; font-weight: 700; }

  .modal-close {
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text-muted);
    width: 30px;
    height: 30px;
    border-radius: 9px;
    font-size: 18px;
    line-height: 1;
    cursor: pointer;
    transition: all 0.15s;
  }

  .modal-close:hover {
    color: var(--text);
    border-color: var(--border-strong);
    background: var(--surface-light);
  }

  /* ========== Preview ========== */
  .preview-overlay {
    position: fixed;
    inset: 0;
    z-index: 1000;
    display: none;
    flex-direction: column;
    background: rgba(6, 9, 20, 0.82);
    backdrop-filter: blur(10px);
    -webkit-backdrop-filter: blur(10px);
  }

  .preview-overlay.active { display: flex; animation: fadeIn 0.2s ease; }

  .preview-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 14px;
    padding: 14px 22px;
    border-bottom: 1px solid var(--border);
    background: rgba(10, 14, 26, 0.6);
    backdrop-filter: blur(14px);
  }

  .preview-filename {
    font-weight: 600;
    font-size: 15px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .preview-actions { display: flex; gap: 10px; flex-shrink: 0; }

  .preview-content {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    overflow: auto;
  }

  .preview-image {
    max-width: 100%;
    max-height: 82vh;
    border-radius: 12px;
    box-shadow: var(--shadow-lg);
  }

  .preview-pdf {
    width: 100%;
    height: 100%;
    border: none;
    border-radius: 12px;
    background: #fff;
  }

  .preview-text {
    width: 100%;
    max-width: 900px;
    max-height: 82vh;
    overflow: auto;
    white-space: pre-wrap;
    word-break: break-word;
    font-family: ui-monospace, 'Cascadia Code', Consolas, monospace;
    font-size: 13px;
    line-height: 1.7;
    background: rgba(5, 8, 18, 0.6);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 22px 24px;
  }

  .preview-video {
    max-width: 100%;
    max-height: 82vh;
    border-radius: 12px;
    background: #000;
    box-shadow: var(--shadow-lg);
  }

  .preview-audio { width: min(560px, 92%); }

  .preview-office {
    width: 100%;
    max-width: 900px;
    max-height: 82vh;
    overflow: auto;
  }

  .preview-loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 14px;
    color: var(--text-muted);
  }

  .preview-error {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    color: var(--error);
    padding: 40px;
  }

  .preview-markdown {
    max-width: 860px;
    width: 100%;
    background: rgba(15, 20, 38, 0.85);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 30px 32px;
    overflow: auto;
    line-height: 1.75;
  }

  .preview-markdown h1, .preview-markdown h2 {
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin: 22px 0 12px;
  }
  .preview-markdown h1 { font-size: 24px; }
  .preview-markdown h2 { font-size: 20px; }
  .preview-markdown h3 { font-size: 17px; margin: 18px 0 10px; }
  .preview-markdown p { margin: 10px 0; }

  .preview-markdown code {
    background: rgba(255, 255, 255, 0.08);
    padding: 2px 7px;
    border-radius: 6px;
    font-size: 13px;
    font-family: ui-monospace, 'Cascadia Code', Consolas, monospace;
  }

  .preview-markdown pre {
    background: rgba(0, 0, 0, 0.35);
    padding: 16px;
    border-radius: 12px;
    overflow: auto;
    margin: 12px 0;
  }
  .preview-markdown pre code { background: transparent; padding: 0; }

  .preview-markdown blockquote {
    border-left: 3px solid var(--primary);
    padding-left: 14px;
    color: var(--text-muted);
    margin: 12px 0;
  }

  .preview-markdown img { max-width: 100%; border-radius: 10px; }
  .preview-markdown a { color: var(--accent); }
  .preview-markdown ul, .preview-markdown ol { padding-left: 24px; margin: 10px 0; }

  .preview-markdown table { border-collapse: collapse; margin: 12px 0; }
  .preview-markdown th, .preview-markdown td {
    border: 1px solid var(--border-strong);
    padding: 8px 12px;
  }

  /* ========== Toast ========== */
  .toast-container {
    position: fixed;
    right: 20px;
    bottom: 20px;
    z-index: 1200;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .toast {
    padding: 12px 18px;
    border-radius: 12px;
    font-size: 14px;
    font-weight: 500;
    max-width: 340px;
    background: rgba(20, 26, 46, 0.94);
    border: 1px solid var(--border-strong);
    box-shadow: var(--shadow-lg);
    backdrop-filter: blur(12px);
    animation: toastIn 0.28s cubic-bezier(0.21, 1.02, 0.73, 1);
  }

  .toast-success { border-left: 3px solid var(--success); }
  .toast-error { border-left: 3px solid var(--error); }
  .toast-info { border-left: 3px solid var(--accent); }

  /* ========== Loading / Spinner ========== */
  .loading-overlay {
    position: fixed;
    inset: 0;
    z-index: 1100;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(6, 9, 20, 0.55);
    backdrop-filter: blur(4px);
  }

  .spinner {
    width: 34px;
    height: 34px;
    border-radius: 50%;
    border: 3px solid rgba(255, 255, 255, 0.12);
    border-top-color: var(--primary-light);
    animation: spin 0.8s linear infinite;
  }

  /* ========== Share Page ========== */
  .share-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
  }

  .share-card {
    width: min(460px, 100%);
    background: rgba(17, 23, 42, 0.8);
    border: 1px solid var(--border-strong);
    border-radius: 20px;
    padding: 36px 32px;
    text-align: center;
    box-shadow: var(--shadow-lg);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    animation: fadeUp 0.4s ease;
  }

  .share-icon { font-size: 52px; margin-bottom: 14px; }
  .share-filename { font-size: 18px; font-weight: 700; word-break: break-all; margin-bottom: 6px; }
  .share-filesize { color: var(--text-muted); font-size: 13px; margin-bottom: 22px; }
  .share-expired { color: var(--error); font-size: 15px; padding: 30px 10px; }

  /* ========== Context Menu ========== */
  .context-menu {
    position: fixed;
    z-index: 1300;
    min-width: 160px;
    background: rgba(20, 26, 46, 0.96);
    border: 1px solid var(--border-strong);
    border-radius: 12px;
    padding: 6px;
    box-shadow: var(--shadow-lg);
    backdrop-filter: blur(14px);
  }

  .context-menu-item {
    padding: 9px 14px;
    border-radius: 8px;
    font-size: 13px;
    cursor: pointer;
    transition: background 0.13s;
  }

  .context-menu-item:hover { background: rgba(99, 102, 241, 0.16); }

  /* ========== Upload Area ========== */
  .upload-area {
    border: 2px dashed rgba(255, 255, 255, 0.18);
    border-radius: var(--radius);
    padding: 42px 20px;
    text-align: center;
    color: var(--text-muted);
    background: rgba(255, 255, 255, 0.02);
    transition: all 0.18s ease;
  }

  .upload-area:hover,
  .upload-area.dragover {
    border-color: var(--primary);
    background: rgba(99, 102, 241, 0.07);
    color: var(--text);
  }

  .upload-area input { display: none; }

  /* ========== Share Source Picker ========== */
  .share-src-tabs { display: flex; gap: 8px; margin-bottom: 14px; }
  .share-src-tab {
    flex: 1; padding: 9px 0; border-radius: 10px; cursor: pointer;
    border: 1px solid rgba(255, 255, 255, 0.10);
    background: rgba(255, 255, 255, 0.03); color: var(--text-muted);
    font-size: 13px; transition: all 0.18s ease;
  }
  .share-src-tab:hover { color: var(--text); border-color: rgba(255, 255, 255, 0.22); }
  .share-src-tab.active {
    color: #fff; border-color: rgba(139, 124, 255, 0.55);
    background: linear-gradient(135deg, rgba(109, 124, 255, 0.25), rgba(157, 92, 255, 0.25));
  }
  .share-browse-bar { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
  .share-browse-path {
    flex: 1; font-size: 12px; color: var(--text-muted); font-family: monospace;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .share-browse-list {
    max-height: 220px; overflow-y: auto;
    border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 10px;
    background: rgba(0, 0, 0, 0.18);
  }
  .share-browse-item {
    display: flex; align-items: center; gap: 8px; padding: 8px 12px;
    cursor: pointer; font-size: 13px; border-bottom: 1px solid rgba(255, 255, 255, 0.04);
  }
  .share-browse-item:last-child { border-bottom: none; }
  .share-browse-item:hover { background: rgba(99, 102, 241, 0.12); }
  .share-browse-item.selected { background: rgba(99, 102, 241, 0.22); }
  .sbi-name { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text); }
  .sbi-size { font-size: 11px; color: var(--text-muted); flex-shrink: 0; }
  .share-browse-loading { padding: 18px; text-align: center; color: var(--text-muted); font-size: 12px; }
  .share-picked {
    display: none; align-items: center; gap: 8px; margin-top: 8px; padding: 8px 12px;
    border-radius: 10px; background: rgba(45, 212, 255, 0.08);
    border: 1px solid rgba(45, 212, 255, 0.25); color: var(--text); font-size: 13px;
  }
  .share-upload-dest { margin-top: 8px; font-size: 12px; color: var(--text-muted); }
  .share-upload-dest b { color: var(--text); }
  .share-modal-upload .upload-area { padding: 24px 16px; cursor: pointer; }

  /* ========== Keyframes ========== */
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes popIn {
    from { opacity: 0; transform: scale(0.92) translateY(8px); }
    to { opacity: 1; transform: scale(1) translateY(0); }
  }
  @keyframes toastIn {
    from { opacity: 0; transform: translateX(30px); }
    to { opacity: 1; transform: translateX(0); }
  }
  @keyframes float {
    from { transform: translate(0, 0); }
    to { transform: translate(24px, 32px); }
  }

  /* ========== Responsive ========== */
  @media (max-width: 720px) {
    .header { padding: 12px 16px; }
    .container { padding: 16px 14px 50px; }
    .file-grid { grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 10px; }
    .file-actions .btn-sm { padding: 4px 8px; font-size: 11px; }
    .toolbar .btn { flex: 1; }
    .tabs { width: 100%; justify-content: space-around; }
    .tab { padding: 8px 12px; font-size: 13px; }
    .login-card { padding: 34px 24px; }
  }
</style>
`;

const LOGIN_PAGE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录 - EdgeStash</title>
  ${CSS_STYLES}
</head>
<body data-reg="__REG_ENABLED__">
  <div class="login-container">
    <div class="login-card">
      <div class="login-header">
        <div class="login-logo">EdgeStash</div>
        <div class="login-subtitle">基于 Cloudflare 的云盘服务</div>
      </div>
      
      <form id="loginForm" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label class="form-label">用户名</label>
          <input type="text" id="email" class="form-input" placeholder="请输入用户名" required>
        </div>
        
        <div class="form-group">
          <label class="form-label">密码</label>
          <input type="password" id="password" class="form-input" placeholder="请输入密码" required>
        </div>
        
        <button type="submit" class="btn btn-primary" style="width: 100%;">
          登录
        </button>
      </form>
      <div id="regLink" style="display: none; text-align: center; margin-top: 14px;">
        <a href="javascript:void(0)" id="regToggle" style="color: #8b7cff; font-size: 13px;">没有账号？注册新账号</a>
      </div>
    </div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>
  
  <script>
    // 注册开关由服务端注入：body[data-reg="1"] 时显示注册入口
    if (document.body.dataset.reg === '1') {
      document.getElementById('regLink').style.display = 'block';
      document.getElementById('regToggle').onclick = function() {
        window.__regMode = !window.__regMode;
        this.textContent = window.__regMode ? '已有账号？去登录' : '没有账号？注册新账号';
        document.querySelector('#loginForm button[type="submit"]').textContent = window.__regMode ? '注册并登录' : '登录';
      };
    }

    async function handleLogin(e) {
      e.preventDefault();
      
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      
      try {
        if (window.__regMode) {
          const regResp = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: email, password })
          });
          const regData = await regResp.json();
          if (!regData.success) {
            showToast(regData.message || '注册失败', 'error');
            return;
          }
          showToast('注册成功，自动登录中', 'success');
        }
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('登录成功', 'success');
          setTimeout(() => {
            window.location.href = '/';
          }, 500);
        } else {
          showToast(data.message || '登录失败', 'error');
        }
      } catch (error) {
        showToast('登录失败: ' + error.message, 'error');
      }
    }
    
    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      container.appendChild(toast);
      
      setTimeout(() => {
        toast.remove();
      }, 3000);
    }
  </script>
</body>
</html>
`;

const INDEX_PAGE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EdgeStash - 云盘</title>
  ${CSS_STYLES}
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/dompurify@3.1.6/dist/purify.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/mammoth@1.6.0/mammoth.browser.min.js"></script>
</head>
<body>
  <div class="header">
    <div class="logo">EdgeStash</div>
    <div class="header-actions">
      <span class="user-chip" id="userChip"></span>
      <button class="btn btn-secondary" id="adminBtn" style="display:none;" onclick="window.location.href='/admin.html'">管理后台</button>
      <button class="btn btn-secondary" onclick="logout()">退出登录</button>
    </div>
  </div>
  
  <div class="container">
    <div class="page-topbar">
      <div class="breadcrumb" id="breadcrumb"></div>

      <div class="toolbar">
        <button class="btn btn-primary" onclick="showNewFolderModal()">📁 新建文件夹</button>
        <button class="btn btn-primary" onclick="showUploadModal()">📤 上传</button>
        <button class="btn btn-secondary" onclick="openSharePicker()">🔗 创建分享</button>
      </div>
    </div>

    <div class="file-panel">
      <div id="fileList" class="file-grid"></div>
      <div id="emptyState" class="empty-state" style="display: none;">
        <div class="empty-icon">📂</div>
        <div>此文件夹为空</div>
      </div>
    </div>
  </div>
  
  <!-- New Folder Modal -->
  <div class="modal-overlay" id="newFolderModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">新建文件夹</div>
        <button class="modal-close" onclick="closeModal('newFolderModal')">&times;</button>
      </div>
      <form onsubmit="createFolder(event)">
        <div class="form-group">
          <label class="form-label">文件夹名称</label>
          <input type="text" id="folderName" class="form-input" placeholder="请输入文件夹名称" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">创建</button>
      </form>
    </div>
  </div>
  
  <!-- Rename Modal -->
  <div class="modal-overlay" id="renameModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">重命名</div>
        <button class="modal-close" onclick="closeModal('renameModal')">&times;</button>
      </div>
      <form onsubmit="renameFile(event)">
        <div class="form-group">
          <label class="form-label">新名称</label>
          <input type="text" id="newFileName" class="form-input" required>
        </div>
        <input type="hidden" id="renameFilePath">
        <button type="submit" class="btn btn-primary" style="width: 100%;">确认</button>
      </form>
    </div>
  </div>
  
  <!-- Upload Modal -->
  <div class="modal-overlay" id="uploadModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">上传到 <span id="uploadDestLabel">/</span></div>
        <button class="modal-close" onclick="closeUploadModal()">&times;</button>
      </div>
      <div class="share-src-tabs">
        <button type="button" class="share-src-tab active" id="upTabFile" onclick="switchUploadMode('file')">📄 选择文件</button>
        <button type="button" class="share-src-tab" id="upTabDir" onclick="switchUploadMode('dir')">📂 选择文件夹</button>
      </div>
      <div class="share-modal-upload">
        <div class="upload-area" id="uploadArea" onclick="triggerUploadPick()">
          <div id="uploadAreaHint">点击选择要上传的文件（可多选）</div>
        </div>
        <input type="file" id="uploadModalFileInput" multiple style="display: none;" onchange="onUploadPick(event)">
        <input type="file" id="uploadModalDirInput" multiple webkitdirectory style="display: none;" onchange="onUploadPick(event)">
        <div id="uploadPicked" class="share-upload-dest" style="display: none;"></div>
      </div>
      <button type="button" class="btn btn-primary" id="uploadStartBtn" style="width: 100%; margin-top: 12px;" onclick="startUploadFromModal()" disabled>开始上传</button>
    </div>
  </div>

  <!-- Share Modal -->
  <div class="modal-overlay" id="shareModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">创建分享链接</div>
        <button class="modal-close" onclick="closeModal('shareModal')">&times;</button>
      </div>
      <div class="share-src-tabs" id="shareSourceTabs" style="display: none;">
        <button type="button" class="share-src-tab active" id="srcTabCloud" onclick="switchShareSource('cloud')">☁️ 从云盘选择</button>
        <button type="button" class="share-src-tab" id="srcTabLocal" onclick="switchShareSource('local')">💻 从本地上传</button>
      </div>
      <div id="shareCloudPicker" style="display: none;">
        <div class="share-browse-bar">
          <button type="button" class="btn btn-sm btn-secondary" onclick="shareBrowseUp()">⬆ 上级</button>
          <span class="share-browse-path" id="shareBrowsePathLabel">/</span>
        </div>
        <div class="share-browse-list" id="shareBrowseList">
          <div class="share-browse-loading">加载中...</div>
        </div>
        <div class="share-picked" id="sharePickedFile"></div>
      </div>
      <div id="shareLocalUpload" style="display: none;" class="share-modal-upload">
        <label class="upload-area">
          <input type="file" id="shareUploadInput" onchange="onShareLocalFile(event)">
          <div>点击选择要上传分享的本地文件</div>
        </label>
        <div id="shareLocalPicked" class="share-upload-dest" style="display: none;">已选择：<b id="shareLocalPickedName"></b></div>
        <div class="share-upload-dest">上传保存位置：<b id="shareUploadDest">/</b>（在「从云盘选择」里切换文件夹可改）</div>
      </div>
      <form onsubmit="createShare(event)">
        <div class="form-group">
          <label class="form-label">分享密码（留空则无密码）</label>
          <input type="text" id="sharePassword" class="form-input" placeholder="可选">
        </div>
        <div class="form-group">
          <label class="form-label">有效期</label>
          <select id="shareExpiry" class="form-select">
            <option value="1h">1小时</option>
            <option value="1d" selected>1天</option>
            <option value="1m">1个月</option>
            <option value="permanent">永久有效</option>
          </select>
        </div>
        <input type="hidden" id="shareFilePath">
        <button type="submit" class="btn btn-primary" style="width: 100%;">创建分享链接</button>
      </form>
    </div>
  </div>
  
  <!-- Share Result Modal -->
  <div class="modal-overlay" id="shareResultModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">分享链接已创建</div>
        <button class="modal-close" onclick="closeModal('shareResultModal')">&times;</button>
      </div>
      <div class="form-group">
        <label class="form-label">分享链接</label>
        <input type="text" id="shareResultUrl" class="form-input" readonly>
      </div>
      <button class="btn btn-primary" style="width: 100%;" onclick="copyShareLink()">复制链接</button>
    </div>
  </div>
  
  <!-- Preview Modal -->
  <div class="preview-overlay" id="previewOverlay">
    <div class="preview-header">
      <div class="preview-filename" id="previewFilename"></div>
      <div class="preview-actions">
        <button class="btn btn-primary" id="previewDownloadBtn">下载</button>
        <button class="btn btn-secondary" onclick="closePreview()">关闭</button>
      </div>
    </div>
    <div class="preview-content" id="previewContent">
      <div class="preview-loading">
        <div class="spinner"></div>
        <div>加载中...</div>
      </div>
    </div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>
  
  <div class="loading-overlay" id="loadingOverlay" style="display: none;">
    <div class="spinner"></div>
  </div>
  
  <script>
    let currentPath = '/';
    let USER_ROLE = 'user';
    let shareMode = 'direct';
    let shareBrowsePath = '/';
    let shareLocalFileObj = null;
    let shareType = 'file';
    let sharePickedPaths = [];
    
    async function checkAuth() {
      try {
        const response = await fetch('/api/auth/check');
        const data = await response.json();
        if (!data.authenticated) {
          window.location.href = '/login.html';
          return;
        }
        USER_ROLE = data.role || 'user';
        const chip = document.getElementById('userChip');
        if (chip && data.email) chip.textContent = data.email;
        const adminBtn = document.getElementById('adminBtn');
        if (adminBtn) adminBtn.style.display = data.role === 'admin' ? '' : 'none';
      } catch (error) {
        window.location.href = '/login.html';
      }
    }
    
    async function loadFiles() {
      showLoading(true);
      try {
        const response = await fetch('/api/files' + currentPath);
        const data = await response.json();
        
        if (!data.success) {
          if (response.status === 401) {
            window.location.href = '/login.html';
            return;
          }
          throw new Error(data.message);
        }
        
        renderBreadcrumb();
        renderFiles(data.folders, data.files);
      } catch (error) {
        showToast('加载文件失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function renderBreadcrumb() {
      const breadcrumb = document.getElementById('breadcrumb');
      const parts = currentPath.split('/').filter(p => p);
      
      let html = '<a href="#" class="breadcrumb-item" onclick="navigateTo(\\'/\\')">🏠 根目录</a>';
      
      let path = '';
      parts.forEach((part, index) => {
        path += '/' + part;
        const isLast = index === parts.length - 1;
        html += '<span class="breadcrumb-separator">/</span>';
        if (isLast) {
          html += '<span class="breadcrumb-item active">' + escapeHtml(part) + '</span>';
        } else {
          html += '<a href="#" class="breadcrumb-item" onclick="navigateTo(\\'' + encodeURIComponent(path) + '\\')">' + escapeHtml(part) + '</a>';
        }
      });
      
      breadcrumb.innerHTML = html;
    }
    
    function renderFiles(folders, files) {
      const fileList = document.getElementById('fileList');
      const emptyState = document.getElementById('emptyState');
      
      if (folders.length === 0 && files.length === 0) {
        fileList.innerHTML = '';
        emptyState.style.display = 'block';
        return;
      }
      
      emptyState.style.display = 'none';
      
      let html = '';
      
      // Render folders
      folders.forEach(folder => {
        html += \`
          <div class="file-item" ondblclick="navigateTo('\${encodeURIComponent(folder.path)}')">
            <div class="file-icon">📁</div>
            <div class="file-name">\${escapeHtml(folder.name)}</div>
            <div class="file-meta">文件夹</div>
            <div class="file-actions">
              <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); showRenameModal('\${encodeURIComponent(folder.path)}', '\${encodeURIComponent(folder.name)}')">重命名</button>
              <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); showShareModal('\${encodeURIComponent(folder.path)}', 'folder')">分享</button>
              <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); downloadFolder('\${encodeURIComponent(folder.path)}')">打包</button>
              <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteFile('\${encodeURIComponent(folder.path)}')">删除</button>
            </div>
          </div>
        \`;
      });
      
      // Render files
      files.forEach(file => {
        const icon = getFileIcon(file.name);
        const previewable = file.previewType ? 'true' : 'false';
        const previewType = file.previewType || '';
        html += \`
          <div class="file-item" ondblclick="handleFileClick('\${encodeURIComponent(file.path)}', '\${previewType}', '\${encodeURIComponent(file.name)}')" data-previewable="\${previewable}">
            <div class="file-icon">\${icon}</div>
            <div class="file-name">\${escapeHtml(file.name)}</div>
            <div class="file-meta">\${file.sizeFormatted}\${previewType ? ' <span class="badge badge-info">可预览</span>' : ''}</div>
            <div class="file-actions">
              \${previewType ? '<button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); previewFile(\\'' + encodeURIComponent(file.path) + '\\', \\'' + previewType + '\\', \\'' + encodeURIComponent(file.name) + '\\')">预览</button>' : ''}
              <button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); downloadFile('\${encodeURIComponent(file.path)}')">下载</button>
              <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); showShareModal('\${encodeURIComponent(file.path)}')">分享</button>
              <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); showRenameModal('\${encodeURIComponent(file.path)}', '\${encodeURIComponent(file.name)}')">重命名</button>
              <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteFile('\${encodeURIComponent(file.path)}')">删除</button>
            </div>
          </div>
        \`;
      });
      
      fileList.innerHTML = html;
    }
    
    function handleFileClick(path, previewType, filename) {
      if (previewType) {
        previewFile(path, previewType, filename);
      } else {
        downloadFile(path);
      }
    }
    
    function getFileIcon(filename) {
      const ext = filename.split('.').pop().toLowerCase();
      const icons = {
        'pdf': '📕',
        'doc': '📘', 'docx': '📘',
        'xls': '📗', 'xlsx': '📗',
        'ppt': '📙', 'pptx': '📙',
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'svg': '🖼️', 'webp': '🖼️',
        'mp3': '🎵', 'wav': '🎵', 'flac': '🎵',
        'mp4': '🎬', 'avi': '🎬', 'mkv': '🎬', 'mov': '🎬',
        'zip': '📦', 'rar': '📦', '7z': '📦', 'tar': '📦', 'gz': '📦',
        'js': '📜', 'ts': '📜', 'py': '📜', 'java': '📜', 'cpp': '📜', 'c': '📜',
        'html': '🌐', 'css': '🎨', 'json': '📋',
        'txt': '📄', 'md': '📝'
      };
      return icons[ext] || '📄';
    }
    
    function navigateTo(path) {
      // onclick 传参是整段 encodeURIComponent 过的（如 %2Fcode），必须先解码再入状态，
      // 否则面包屑显示编码名、后续请求全带编码路径
      try { path = decodeURIComponent(path); } catch (e) { /* 非法编码则按原样 */ }
      currentPath = path;
      loadFiles();
    }
    
    // ========== Preview Functions ==========
    
    async function previewFile(path, previewType, filename) {
      const overlay = document.getElementById('previewOverlay');
      const content = document.getElementById('previewContent');
      const filenameEl = document.getElementById('previewFilename');
      const downloadBtn = document.getElementById('previewDownloadBtn');
      
      filenameEl.textContent = filename;
      downloadBtn.onclick = () => downloadFile(path);
      
      // Show loading
      content.innerHTML = '<div class="preview-loading"><div class="spinner"></div><div>加载中...</div></div>';
      overlay.classList.add('active');
      
      try {
        const previewUrl = '/api/preview' + encodePath(decodeURIComponent(path));
        
        switch (previewType) {
          case 'image':
            content.innerHTML = '<img class="preview-image" src="' + previewUrl + '" alt="' + escapeHtml(filename) + '">';
            break;
            
          case 'pdf':
            content.innerHTML = '<iframe class="preview-pdf" src="' + previewUrl + '"></iframe>';
            break;
            
          case 'text':
            const textResponse = await fetch(previewUrl);
            const text = await textResponse.text();
            const ext = filename.split('.').pop().toLowerCase();
            
            if (ext === 'md') {
              // Render Markdown
              const htmlContent = (window.DOMPurify ? DOMPurify.sanitize(marked.parse(text)) : escapeHtml(text));
              content.innerHTML = '<div class="preview-markdown">' + htmlContent + '</div>';
            } else if (ext === 'json') {
              // Pretty print JSON
              try {
                const json = JSON.parse(text);
                content.innerHTML = '<pre class="preview-text">' + escapeHtml(JSON.stringify(json, null, 2)) + '</pre>';
              } catch {
                content.innerHTML = '<pre class="preview-text">' + escapeHtml(text) + '</pre>';
              }
            } else {
              content.innerHTML = '<pre class="preview-text">' + escapeHtml(text) + '</pre>';
            }
            break;
            
          case 'video':
            content.innerHTML = '<video class="preview-video" controls autoplay><source src="' + previewUrl + '"></video>';
            break;
            
          case 'audio':
            content.innerHTML = '<audio class="preview-audio" controls autoplay><source src="' + previewUrl + '"></audio>';
            break;
            
          case 'word':
            // Use Mammoth.js to convert docx to HTML
            const docxResponse = await fetch(previewUrl);
            const docxArrayBuffer = await docxResponse.arrayBuffer();
            const result = await mammoth.convertToHtml({ arrayBuffer: docxArrayBuffer });
            content.innerHTML = '<div class="preview-markdown">' + result.value + '</div>';
            break;
            
          default:
            content.innerHTML = '<div class="preview-error">不支持预览此文件类型</div>';
        }
      } catch (error) {
        content.innerHTML = '<div class="preview-error">预览加载失败: ' + escapeHtml(error.message) + '</div>';
      }
    }
    
    function closePreview() {
      const overlay = document.getElementById('previewOverlay');
      overlay.classList.remove('active');
      // Clear content to stop any playing media
      document.getElementById('previewContent').innerHTML = '';
    }
    
    // Close preview on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closePreview();
      }
    });
    
    // ========== File Operations ==========
    
    // ===== 上传弹窗（文件/文件夹统一入口，样式对齐创建分享弹窗）=====
    let uploadMode = 'file'; // 'file' | 'dir'
    let uploadPickedFiles = [];

    function fmtSize(bytes) {
      if (bytes < 1024) return bytes + ' B';
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
      if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
      return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
    }

    function showUploadModal() {
      uploadPickedFiles = [];
      switchUploadMode('file');
      document.getElementById('uploadDestLabel').textContent = currentPath;
      document.getElementById('uploadModal').classList.add('active');
    }

    function closeUploadModal() {
      document.getElementById('uploadModal').classList.remove('active');
      resetUploadModalState();
    }

    function resetUploadModalState() {
      uploadPickedFiles = [];
      const fi = document.getElementById('uploadModalFileInput');
      const di = document.getElementById('uploadModalDirInput');
      if (fi) fi.value = '';
      if (di) di.value = '';
      renderUploadPicked();
    }

    function switchUploadMode(mode) {
      uploadMode = mode;
      document.getElementById('upTabFile').classList.toggle('active', mode === 'file');
      document.getElementById('upTabDir').classList.toggle('active', mode === 'dir');
      document.getElementById('uploadAreaHint').textContent = mode === 'file'
        ? '点击选择要上传的文件（可多选）'
        : '点击选择要上传的文件夹（保留目录结构）';
      // 切换模式时清空已选，避免文件/文件夹选择混在一起
      resetUploadModalState();
    }

    function triggerUploadPick() {
      const input = uploadMode === 'file'
        ? document.getElementById('uploadModalFileInput')
        : document.getElementById('uploadModalDirInput');
      input.click();
    }

    function onUploadPick(event) {
      uploadPickedFiles = Array.from(event.target.files || []);
      renderUploadPicked();
    }

    function renderUploadPicked() {
      const box = document.getElementById('uploadPicked');
      const btn = document.getElementById('uploadStartBtn');
      if (!uploadPickedFiles.length) {
        box.style.display = 'none';
        box.innerHTML = '';
        btn.disabled = true;
        btn.textContent = '开始上传';
        return;
      }
      let total = 0;
      uploadPickedFiles.forEach(f => { total += (f.size || 0); });
      let label;
      if (uploadMode === 'dir') {
        const rel = uploadPickedFiles[0].webkitRelativePath || uploadPickedFiles[0].name;
        const top = rel.split('/')[0];
        label = '已选择文件夹「' + top + '」：' + uploadPickedFiles.length + ' 个文件，共 ' + fmtSize(total);
      } else {
        label = '已选择 ' + uploadPickedFiles.length + ' 个文件，共 ' + fmtSize(total);
      }
      box.textContent = label;
      box.style.display = 'block';
      btn.disabled = false;
      btn.textContent = '开始上传（' + uploadPickedFiles.length + ' 个文件）';
    }

    function startUploadFromModal() {
      if (!uploadPickedFiles.length) return;
      const files = uploadPickedFiles;
      document.getElementById('uploadModal').classList.remove('active');
      resetUploadModalState();
      if (uploadMode === 'dir') {
        uploadDirList(files);
      } else {
        uploadFilesList(files);
      }
    }

    async function uploadFilesList(files) {
      if (!files.length) return;

      showLoading(true);

      for (const file of files) {
        try {
          const formData = new FormData();
          formData.append('file', file);

          const response = await fetch('/api/files' + currentPath, {
            method: 'POST',
            body: formData
          });

          const data = await response.json();

          if (data.success) {
            showToast('文件 ' + file.name + ' 上传成功', 'success');
          } else {
            showToast('文件 ' + file.name + ' 上传失败: ' + data.message, 'error');
          }
        } catch (error) {
          showToast('文件 ' + file.name + ' 上传失败: ' + error.message, 'error');
        }
      }

      loadFiles();
    }

    // 文件夹整体上传（webkitdirectory）：逐级建目录后逐个上传
    async function uploadDirList(files) {
      if (!files.length) return;
      showLoading(true);
      try {
        const base = currentPath === '/' ? '' : currentPath.slice(0, -1);
        const dirSet = new Set();
        files.forEach(f => {
          const parts = (f.webkitRelativePath || f.name).split('/');
          parts.pop();
          let cur = '';
          parts.forEach(p => { cur += '/' + p; dirSet.add(base + cur); });
        });
        for (const dir of dirSet) {
          await fetch('/api/folders', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: dir })
          });
        }
        let ok = 0, fail = 0;
        for (const f of files) {
          const parts = (f.webkitRelativePath || f.name).split('/');
          parts.pop();
          const dir = base + parts.map(p => '/' + p).join('');
          const fd = new FormData();
          fd.append('file', f);
          try {
            const resp = await fetch('/api/files' + dir, { method: 'POST', body: fd });
            const data = await resp.json();
            data.success ? ok++ : fail++;
          } catch (e) { fail++; }
        }
        if (fail === 0) showToast('文件夹上传完成（' + ok + ' 个文件）', 'success');
        else showToast('文件夹上传：成功 ' + ok + '，失败 ' + fail, 'error');
        loadFiles();
      } catch (e) {
        showToast('文件夹上传失败: ' + e.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function showNewFolderModal() {
      document.getElementById('folderName').value = '';
      document.getElementById('newFolderModal').classList.add('active');
    }
    
    async function createFolder(event) {
      event.preventDefault();
      const name = document.getElementById('folderName').value.trim();
      
      if (!name) {
        showToast('请输入文件夹名称', 'error');
        return;
      }
      
      showLoading(true);
      closeModal('newFolderModal');
      
      try {
        let folderPath = currentPath;
        if (!folderPath.endsWith('/')) folderPath += '/';
        folderPath += name;
        
        const response = await fetch('/api/folders', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: folderPath })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('文件夹创建成功', 'success');
          loadFiles();
        } else {
          showToast('创建失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('创建失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function showRenameModal(path, currentName) {
      document.getElementById('renameFilePath').value = path;
      document.getElementById('newFileName').value = currentName;
      document.getElementById('renameModal').classList.add('active');
    }
    
    async function renameFile(event) {
      event.preventDefault();
      const path = document.getElementById('renameFilePath').value;
      const newName = document.getElementById('newFileName').value.trim();
      
      if (!newName) {
        showToast('请输入新名称', 'error');
        return;
      }
      
      showLoading(true);
      closeModal('renameModal');
      
      try {
        const response = await fetch('/api/files' + path, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ newName })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('重命名成功', 'success');
          loadFiles();
        } else {
          showToast('重命名失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('重命名失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    async function deleteFile(path) {
      if (!confirm('确定要删除吗？此操作不可恢复。')) return;
      
      showLoading(true);
      
      try {
        const response = await fetch('/api/files' + path, {
          method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('删除成功', 'success');
          loadFiles();
        } else {
          showToast('删除失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('删除失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function encodePath(p) {
      return p.split('/').map(function(s) { return encodeURIComponent(s); }).join('/');
    }

    async function downloadFile(path) {
      window.open('/api/download' + encodePath(decodeURIComponent(path)), '_blank');
    }

    function downloadFolder(path) {
      window.open('/api/download-folder' + encodeURIComponent(decodeURIComponent(path)), '_blank');
    }
    
    function showShareModal(path, type) {
      shareMode = 'direct';
      shareType = type || 'file';
      sharePickedPaths = [];
      document.getElementById('shareSourceTabs').style.display = 'none';
      document.getElementById('shareCloudPicker').style.display = 'none';
      document.getElementById('shareLocalUpload').style.display = 'none';
      document.getElementById('shareFilePath').value = path;
      document.getElementById('sharePassword').value = '';
      document.getElementById('shareExpiry').value = '1d';
      document.getElementById('shareModal').classList.add('active');
    }

    function openSharePicker() {
      shareMode = 'cloud';
      shareType = 'file';
      sharePickedPaths = [];
      shareLocalFileObj = null;
      const isAdmin = (USER_ROLE === 'admin');
      document.getElementById('srcTabLocal').style.display = isAdmin ? '' : 'none';
      document.getElementById('srcTabCloud').classList.add('active');
      document.getElementById('srcTabLocal').classList.remove('active');
      document.getElementById('shareCloudPicker').style.display = 'block';
      document.getElementById('shareLocalUpload').style.display = 'none';
      document.getElementById('shareSourceTabs').style.display = 'flex';
      document.getElementById('sharePickedFile').style.display = 'none';
      document.getElementById('shareLocalPicked').style.display = 'none';
      document.getElementById('shareFilePath').value = '';
      document.getElementById('sharePassword').value = '';
      document.getElementById('shareExpiry').value = '1d';
      document.getElementById('shareUploadInput').value = '';
      shareBrowsePath = currentPath;
      loadShareBrowse();
      document.getElementById('shareModal').classList.add('active');
    }

    function switchShareSource(src) {
      shareMode = src;
      document.getElementById('srcTabCloud').classList.toggle('active', src === 'cloud');
      document.getElementById('srcTabLocal').classList.toggle('active', src === 'local');
      document.getElementById('shareCloudPicker').style.display = src === 'cloud' ? 'block' : 'none';
      document.getElementById('shareLocalUpload').style.display = src === 'local' ? 'block' : 'none';
      if (src === 'local') {
        document.getElementById('shareFilePath').value = '';
        sharePickedPaths = [];
      } else {
        document.getElementById('sharePickedFile').style.display = document.getElementById('shareFilePath').value ? 'flex' : 'none';
      }
    }

    async function loadShareBrowse() {
      const listEl = document.getElementById('shareBrowseList');
      document.getElementById('shareBrowsePathLabel').textContent = shareBrowsePath;
      document.getElementById('shareUploadDest').textContent = shareBrowsePath;
      listEl.innerHTML = '<div class="share-browse-loading">加载中...</div>';
      try {
        const response = await fetch('/api/files' + shareBrowsePath);
        const data = await response.json();
        if (!data.success) throw new Error(data.message);
        let html = '';
        data.folders.forEach(function(folder) {
          html += '<div class="share-browse-item" onclick="shareBrowseEnter(\\'' + encodeURIComponent(folder.path) + '\\')"><span>📁</span><span class="sbi-name">' + escapeHtml(folder.name) + '</span><span class="sbi-size"></span></div>';
        });
        data.files.forEach(function(file) {
          html += '<div class="share-browse-item" data-fp="' + escapeHtml(file.path) + '" onclick="sharePickFile(\\'' + encodeURIComponent(file.path) + '\\', this)"><span>' + getFileIcon(file.name) + '</span><span class="sbi-name">' + escapeHtml(file.name) + '</span><span class="sbi-size">' + file.sizeFormatted + '</span></div>';
        });
        if (!html) html = '<div class="share-browse-loading">此文件夹为空</div>';
        listEl.innerHTML = html;
      } catch (e) {
        listEl.innerHTML = '<div class="share-browse-loading">加载失败: ' + escapeHtml(e.message) + '</div>';
      }
    }

    function shareBrowseEnter(path) {
      shareBrowsePath = decodeURIComponent(path);
      loadShareBrowse();
    }

    function shareBrowseUp() {
      if (shareBrowsePath === '/') return;
      let parts = shareBrowsePath.replace(/^\\/+|\\/+$/g, '').split('/').filter(Boolean);
      parts.pop();
      shareBrowsePath = parts.length ? '/' + parts.join('/') + '/' : '/';
      loadShareBrowse();
    }

    function sharePickFile(path, el) {
      path = decodeURIComponent(path);
      const idx = sharePickedPaths.indexOf(path);
      if (idx >= 0) {
        sharePickedPaths.splice(idx, 1);
        el.classList.remove('selected');
      } else {
        sharePickedPaths.push(path);
        el.classList.add('selected');
      }
      document.getElementById('shareFilePath').value = sharePickedPaths.length ? sharePickedPaths[sharePickedPaths.length - 1] : '';
      const picked = document.getElementById('sharePickedFile');
      if (sharePickedPaths.length) {
        picked.textContent = sharePickedPaths.length > 1 ? ('已选择 ' + sharePickedPaths.length + ' 个文件') : ('已选择: ' + sharePickedPaths[0]);
        picked.style.display = 'flex';
      } else {
        picked.style.display = 'none';
      }
    }

    function onShareLocalFile(event) {
      shareLocalFileObj = event.target.files[0] || null;
      const picked = document.getElementById('shareLocalPicked');
      if (shareLocalFileObj) {
        document.getElementById('shareLocalPickedName').textContent = shareLocalFileObj.name;
        picked.style.display = 'block';
      } else {
        picked.style.display = 'none';
      }
    }

    async function createShare(event) {
      event.preventDefault();
      let filePath = document.getElementById('shareFilePath').value;
      const password = document.getElementById('sharePassword').value;
      const expiresIn = document.getElementById('shareExpiry').value;

      let shareBody;
      if (shareType === 'folder') {
        if (!filePath) {
          showToast('缺少文件夹路径', 'error');
          return;
        }
        shareBody = { type: 'folder', folderPath: filePath, password, expiresIn };
      } else if (shareMode === 'cloud' && sharePickedPaths.length > 1) {
        shareBody = { type: 'multi', items: sharePickedPaths.slice(), password, expiresIn };
      } else {
        if (shareMode === 'cloud' && !filePath) {
          showToast('请先从云盘选择要分享的文件', 'error');
          return;
        }
        if (shareMode === 'local' && !shareLocalFileObj) {
          showToast('请先选择要上传的本地文件', 'error');
          return;
        }
        shareBody = { filePath, password, expiresIn };
      }

      showLoading(true);
      closeModal('shareModal');

      try {
        if (shareMode === 'local') {
          const fd = new FormData();
          fd.append('file', shareLocalFileObj);
          const upResp = await fetch('/api/files' + shareBrowsePath, { method: 'POST', body: fd });
          const upData = await upResp.json();
          if (!upData.success) throw new Error(upData.message || '上传失败');
          filePath = upData.path;
          shareBody = { filePath, password, expiresIn };
        }

        const response = await fetch('/api/share', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(shareBody)
        });
        
        const data = await response.json();
        
        if (data.success) {
          const fullUrl = window.location.origin + data.shareUrl;
          document.getElementById('shareResultUrl').value = fullUrl;
          document.getElementById('shareResultModal').classList.add('active');
          if (shareMode === 'local') loadFiles();
        } else {
          showToast('创建分享链接失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('创建分享链接失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function copyShareLink() {
      const input = document.getElementById('shareResultUrl');
      input.select();
      document.execCommand('copy');
      showToast('链接已复制到剪贴板', 'success');
    }
    
    async function logout() {
      try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/login.html';
      } catch (error) {
        window.location.href = '/login.html';
      }
    }
    
    function closeModal(id) {
      document.getElementById(id).classList.remove('active');
    }
    
    function showLoading(show) {
      document.getElementById('loadingOverlay').style.display = show ? 'flex' : 'none';
    }
    
    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      container.appendChild(toast);
      
      setTimeout(() => {
        toast.remove();
      }, 3000);
    }
    
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    
    // Initialize
    checkAuth();
    loadFiles();
  </script>
</body>
</html>
`;

const ADMIN_PAGE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理后台 - EdgeStash</title>
  ${CSS_STYLES}
</head>
<body>
  <div class="header">
    <div class="logo">EdgeStash 管理后台</div>
    <div class="header-actions">
      <span class="user-chip" id="userChip"></span>
      <button class="btn btn-secondary" onclick="window.location.href='/'">返回云盘</button>
      <button class="btn btn-secondary" onclick="logout()">退出登录</button>
    </div>
  </div>
  
  <div class="container">
    <div class="tabs">
      <button class="tab active" onclick="switchTab('shares')">分享链接</button>
      <button class="tab" onclick="switchTab('users')">授权用户</button>
      <button class="tab" onclick="switchTab('storage')">存储上限</button>
    </div>
    
    <!-- Shares Tab -->
    <div id="sharesTab" class="tab-content active">
      <div class="card">
        <div class="card-header">
          <div class="card-title">分享链接管理</div>
          <button class="btn btn-sm btn-danger" id="batchDeleteSharesBtn" onclick="batchDeleteShares()" disabled>删除选中</button>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th style="width:36px;"><input type="checkbox" id="sharesSelectAll" onchange="toggleAllShares(this.checked)" style="vertical-align:middle;"></th>
                <th>文件名</th>
                <th>分享ID</th>
                <th>密码保护</th>
                <th>浏览次数</th>
                <th>下载次数</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="sharesTable"></tbody>
          </table>
        </div>
      </div>
    </div>
    
    <!-- Users Tab -->
    <div id="usersTab" class="tab-content">
      <div class="card">
        <div class="card-header">
          <div class="card-title">授权用户管理</div>
          <button class="btn btn-primary" onclick="showAddUserModal()">添加用户</button>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>用户名</th>
                <th>角色</th>
                <th>存储（已用 / 配额）</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="usersTable"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Storage Tab -->
    <div id="storageTab" class="tab-content">
      <div class="card">
        <div class="card-header">
          <div class="card-title">存储上限</div>
        </div>
        <div class="form-group">
          <label class="form-label">当前用量</label>
          <div id="storageUsage" style="font-size: 15px; color: var(--text);">加载中...</div>
          <div style="margin-top: 10px; height: 8px; border-radius: 4px; background: rgba(255,255,255,0.08); overflow: hidden;">
            <div id="storageBar" style="height: 100%; width: 0%; background: linear-gradient(90deg, #6d7cff, #2dd4ff); transition: width 0.3s ease;"></div>
          </div>
        </div>
        <form onsubmit="saveStorage(event)">
          <div class="form-group">
            <label class="form-label">全盘存储上限（GB）</label>
            <input type="number" id="storageCap" class="form-input" placeholder="如：9.5" min="0.01" step="any" required>
            <div style="margin-top: 6px; font-size: 12px; color: var(--text-muted);">R2 免费额度 10GB，默认 9.5GB。普通用户超限时提示联系管理员，管理员超限时提示调整上限。</div>
          </div>
          <button type="submit" class="btn btn-primary">保存上限</button>
        </form>
      </div>
    </div>
  </div>
  
  <!-- Add User Modal -->
  <div class="modal-overlay" id="addUserModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">添加授权用户</div>
        <button class="modal-close" onclick="closeModal('addUserModal')">&times;</button>
      </div>
      <form onsubmit="addUser(event)">
        <div class="form-group">
          <label class="form-label">用户名</label>
          <input type="text" id="newUserEmail" class="form-input" placeholder="自定义用户名，不能重复" required>
        </div>
        <div class="form-group">
          <label class="form-label">密码</label>
          <input type="text" id="newUserPassword" class="form-input" placeholder="请输入密码" required>
        </div>
        <div class="form-group">
          <label class="form-label">存储配额（留空 = 不限）</label>
          <div style="display: flex; gap: 8px;">
            <input type="number" id="newUserQuota" class="form-input" placeholder="如：10" min="0" step="any">
            <select id="newUserQuotaUnit" class="form-select" style="width: 110px; flex-shrink: 0;">
              <option value="GB" selected>GB</option>
              <option value="MB">MB</option>
            </select>
          </div>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">添加用户</button>
      </form>
    </div>
  </div>
  
  <!-- Edit Quota Modal -->
  <div class="modal-overlay" id="editQuotaModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">修改存储配额</div>
        <button class="modal-close" onclick="closeModal('editQuotaModal')">&times;</button>
      </div>
      <form onsubmit="saveQuota(event)">
        <div class="form-group">
          <label class="form-label">用户</label>
          <input type="text" id="quotaEmail" class="form-input" readonly>
        </div>
        <div class="form-group">
          <label class="form-label">存储配额（留空 = 不限）</label>
          <div style="display: flex; gap: 8px;">
            <input type="number" id="quotaValue" class="form-input" placeholder="如：10" min="0" step="any">
            <select id="quotaUnit" class="form-select" style="width: 110px; flex-shrink: 0;">
              <option value="GB" selected>GB</option>
              <option value="MB">MB</option>
            </select>
          </div>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">保存</button>
      </form>
    </div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>
  
  <div class="loading-overlay" id="loadingOverlay" style="display: none;">
    <div class="spinner"></div>
  </div>
  
  <script>
    async function checkAdminAuth() {
      try {
        const response = await fetch('/api/auth/check');
        const data = await response.json();
        if (!data.authenticated || data.role !== 'admin') {
          window.location.href = '/login.html';
          return;
        }
        const chip = document.getElementById('userChip');
        if (chip && data.email) chip.textContent = data.email;
      } catch (error) {
        window.location.href = '/login.html';
      }
    }
    
    function switchTab(tab) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      event.target.classList.add('active');
      document.getElementById(tab + 'Tab').classList.add('active');
      
      if (tab === 'shares') loadShares();
      else if (tab === 'users') loadUsers();
      else if (tab === 'storage') loadStorage();
    }
    
    async function loadStorage() {
      try {
        const resp = await fetch('/api/admin/storage');
        const data = await resp.json();
        if (data.success) {
          document.getElementById('storageUsage').textContent = data.usedFormatted + ' / ' + data.capFormatted;
          const pct = data.capBytes > 0 ? Math.min(100, (data.usedBytes / data.capBytes) * 100) : 0;
          document.getElementById('storageBar').style.width = pct.toFixed(1) + '%';
          document.getElementById('storageCap').value = (data.capBytes / (1024 * 1024 * 1024)).toFixed(2);
        } else {
          showToast('加载存储信息失败: ' + data.message, 'error');
        }
      } catch (e) {
        showToast('加载存储信息失败: ' + e.message, 'error');
      }
    }

    async function saveStorage(event) {
      event.preventDefault();
      const gb = Number(document.getElementById('storageCap').value);
      if (!(gb > 0)) { showToast('请输入有效的上限（GB）', 'error'); return; }
      showLoading(true);
      try {
        const resp = await fetch('/api/admin/storage', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ capBytes: Math.round(gb * 1024 * 1024 * 1024) })
        });
        const data = await resp.json();
        if (data.success) { showToast('存储上限已更新', 'success'); loadStorage(); }
        else showToast('保存失败: ' + data.message, 'error');
      } catch (e) {
        showToast('保存失败: ' + e.message, 'error');
      } finally {
        showLoading(false);
      }
    }

    async function loadShares() {
      showLoading(true);
      try {
        const response = await fetch('/api/admin/shares');
        const data = await response.json();
        
        if (data.success) {
          const tbody = document.getElementById('sharesTable');
          
          if (data.shares.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted);">暂无分享链接</td></tr>';
            updateShareBatchBar();
            return;
          }

          tbody.innerHTML = data.shares.map(share => \`
            <tr>
              <td><input type="checkbox" class="share-check" data-share-id="\${share.shareId}" onchange="updateShareBatchBar()" style="vertical-align:middle;"></td>
              <td>\${escapeHtml(share.fileName)}</td>
              <td><code>\${share.shareId}</code></td>
              <td>\${share.passwordHash ? '是' : '否'}</td>
              <td>\${share.viewCount}</td>
              <td>\${share.downloadCount}</td>
              <td>
                \${share.isExpired 
                  ? '<span class="badge badge-error">已过期</span>' 
                  : '<span class="badge badge-success">有效</span>'}
              </td>
              <td>
                <button class="btn btn-sm btn-secondary" onclick="copyShareLink('\${share.shareId}')">复制链接</button>
                <button class="btn btn-sm btn-danger" onclick="deleteShare('\${share.shareId}')">删除</button>
              </td>
            </tr>
          \`).join('');
          const selectAll = document.getElementById('sharesSelectAll');
          if (selectAll) selectAll.checked = false;
          updateShareBatchBar();
        }
      } catch (error) {
        showToast('加载分享列表失败', 'error');
      } finally {
        showLoading(false);
      }
    }

    function toggleAllShares(checked) {
      document.querySelectorAll('.share-check').forEach(cb => { cb.checked = checked; });
      updateShareBatchBar();
    }

    function updateShareBatchBar() {
      const btn = document.getElementById('batchDeleteSharesBtn');
      if (!btn) return;
      const count = document.querySelectorAll('.share-check:checked').length;
      btn.disabled = count === 0;
      btn.textContent = count > 0 ? '删除选中(' + count + ')' : '删除选中';
    }

    async function batchDeleteShares() {
      const ids = Array.from(document.querySelectorAll('.share-check:checked')).map(cb => cb.getAttribute('data-share-id'));
      if (ids.length === 0) return;
      if (!confirm('确定要删除选中的 ' + ids.length + ' 条分享链接吗？删除后链接立即失效。')) return;

      showLoading(true);
      try {
        const response = await fetch('/api/admin/shares/batch-delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ shareIds: ids })
        });
        const data = await response.json();
        if (data.success) {
          showToast(data.message || '批量删除完成', 'success');
          loadShares();
        } else {
          showToast('批量删除失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('批量删除失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function showOneTimePw(user, pw) {
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay active';
      const modal = document.createElement('div');
      modal.className = 'modal';
      const head = document.createElement('div');
      head.className = 'modal-header';
      const title = document.createElement('div');
      title.className = 'modal-title';
      title.textContent = '密码已重置（仅显示一次）';
      const close = document.createElement('button');
      close.className = 'modal-close';
      close.textContent = '×';
      close.onclick = function() { overlay.remove(); };
      head.appendChild(title);
      head.appendChild(close);
      const body = document.createElement('div');
      body.style.cssText = 'padding: 8px 0 4px; color: var(--text-muted); font-size: 13px;';
      body.textContent = '用户 ' + user + ' 的新密码，关闭后将无法再次查看：';
      const input = document.createElement('input');
      input.className = 'form-input';
      input.readOnly = true;
      input.value = pw;
      input.style.marginTop = '12px';
      const btn = document.createElement('button');
      btn.className = 'btn btn-primary';
      btn.style.cssText = 'width: 100%; margin-top: 12px;';
      btn.textContent = '复制并关闭';
      btn.onclick = function() {
        input.select();
        document.execCommand('copy');
        overlay.remove();
      };
      modal.appendChild(head);
      modal.appendChild(body);
      modal.appendChild(input);
      modal.appendChild(btn);
      overlay.appendChild(modal);
      document.body.appendChild(overlay);
    }

    async function resetUserPassword(encEmail) {
      if (!confirm('确定重置该用户的密码？将生成一次性随机密码，旧密码立即失效。')) return;
      showLoading(true);
      try {
        const resp = await fetch('/api/admin/users/' + encEmail + '/reset-password', { method: 'POST' });
        const data = await resp.json();
        if (data.success) {
          showOneTimePw(decodeURIComponent(encEmail), data.oneTimePassword);
        } else {
          showToast('重置失败: ' + data.message, 'error');
        }
      } catch (e) {
        showToast('重置失败: ' + e.message, 'error');
      } finally {
        showLoading(false);
      }
    }

    async function loadUsers() {
      showLoading(true);
      try {
        const response = await fetch('/api/admin/users');
        const data = await response.json();
        
        if (data.success) {
          const tbody = document.getElementById('usersTable');
          
          if (data.users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">暂无授权用户</td></tr>';
            return;
          }
          
          tbody.innerHTML = data.users.map(user => \`
            <tr>
              <td>\${escapeHtml(user.email)}</td>
              <td>\${user.role === 'admin' ? '管理员' : '普通用户'}</td>
              <td>\${user.usedFormatted || '0 B'} / \${user.quotaBytes > 0 ? user.quotaFormatted : '不限'}</td>
              <td>\${user.createdAt ? new Date(user.createdAt).toLocaleString() : '-'}</td>
              <td>
                <button class="btn btn-sm btn-secondary" onclick="showEditQuota('\${encodeURIComponent(user.email)}')">配额</button>
                <button class="btn btn-sm btn-secondary" onclick="resetUserPassword('\${encodeURIComponent(user.email)}')">重置密码</button>
                <button class="btn btn-sm btn-danger" onclick="deleteUser('\${encodeURIComponent(user.email)}')">撤销授权</button>
              </td>
            </tr>
          \`).join('');
        }
      } catch (error) {
        showToast('加载用户列表失败', 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function showAddUserModal() {
      document.getElementById('newUserEmail').value = '';
      document.getElementById('newUserPassword').value = '';
      document.getElementById('newUserQuota').value = '';
      document.getElementById('newUserQuotaUnit').value = 'GB';
      document.getElementById('addUserModal').classList.add('active');
    }
    
    function readQuotaInput(valueId, unitId) {
      const v = parseFloat(document.getElementById(valueId).value);
      const unit = document.getElementById(unitId).value;
      if (isNaN(v) || v <= 0) return 0;
      return Math.round(v * (unit === 'GB' ? 1024 * 1024 * 1024 : 1024 * 1024));
    }
    
    function showEditQuota(email) {
      document.getElementById('quotaEmail').value = decodeURIComponent(email);
      document.getElementById('quotaValue').value = '';
      document.getElementById('quotaUnit').value = 'GB';
      document.getElementById('editQuotaModal').classList.add('active');
    }
    
    async function saveQuota(event) {
      event.preventDefault();
      const email = document.getElementById('quotaEmail').value;
      const quotaBytes = readQuotaInput('quotaValue', 'quotaUnit');
      
      showLoading(true);
      closeModal('editQuotaModal');
      
      try {
        const response = await fetch('/api/admin/users/' + encodeURIComponent(email), {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ quotaBytes })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('配额已更新', 'success');
          loadUsers();
        } else {
          showToast('保存失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('保存失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    async function addUser(event) {
      event.preventDefault();
      const email = document.getElementById('newUserEmail').value;
      const password = document.getElementById('newUserPassword').value;
      const quotaBytes = readQuotaInput('newUserQuota', 'newUserQuotaUnit');
      
      showLoading(true);
      closeModal('addUserModal');
      
      try {
        const response = await fetch('/api/admin/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password, quotaBytes })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('用户添加成功', 'success');
          loadUsers();
        } else {
          showToast('添加失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('添加失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    async function deleteUser(email) {
      if (!confirm('确定要撤销该用户的授权吗？')) return;
      
      showLoading(true);
      
      try {
        const response = await fetch('/api/admin/users/' + email, {
          method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('用户已删除', 'success');
          loadUsers();
        } else {
          showToast('删除失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('删除失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    async function deleteShare(shareId) {
      if (!confirm('确定要删除该分享链接吗？')) return;
      
      showLoading(true);
      
      try {
        const response = await fetch('/api/admin/shares/' + shareId, {
          method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('分享链接已删除', 'success');
          loadShares();
        } else {
          showToast('删除失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('删除失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function copyShareLink(shareId) {
      const url = window.location.origin + '/s/' + shareId;
      navigator.clipboard.writeText(url).then(() => {
        showToast('链接已复制', 'success');
      }).catch(() => {
        showToast('复制失败', 'error');
      });
    }
    
    async function logout() {
      try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/login.html';
      } catch (error) {
        window.location.href = '/login.html';
      }
    }
    
    function closeModal(id) {
      document.getElementById(id).classList.remove('active');
    }
    
    function showLoading(show) {
      document.getElementById('loadingOverlay').style.display = show ? 'flex' : 'none';
    }
    
    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      container.appendChild(toast);
      
      setTimeout(() => {
        toast.remove();
      }, 3000);
    }
    
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }
    
    // Initialize
    checkAdminAuth();
    loadShares();
  </script>
</body>
</html>
`;

const SHARE_PAGE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>文件分享 - EdgeStash</title>
  ${CSS_STYLES}
</head>
<body>
  <div class="share-container">
    <div class="share-card" id="shareCard">
      <div id="loadingState">
        <div class="spinner" style="margin: 0 auto 20px;"></div>
        <div>加载中...</div>
      </div>

      <div id="expiredState" style="display: none;">
        <div class="share-icon">⚠️</div>
        <div class="share-expired">分享链接已过期或不存在</div>
        <p style="color: var(--text-muted); margin-top: 16px;">请联系分享者获取新的链接</p>
      </div>

      <div id="shareContent" style="display: none;">
        <div class="share-icon" id="shareIcon">📄</div>
        <div class="share-filename" id="fileName"></div>
        <div class="share-filesize" id="fileSize"></div>

        <div id="passwordForm" style="display: none;">
          <div class="form-group">
            <label class="form-label">请输入分享密码</label>
            <input type="password" id="sharePassword" class="form-input" placeholder="输入密码">
          </div>
        </div>

        <div id="fileListView" style="display: none; max-height: 320px; overflow-y: auto; text-align: left; margin-top: 12px; border: 1px solid var(--border-color, rgba(128,128,128,.25)); border-radius: 10px; padding: 6px;"></div>

        <button class="btn btn-primary" style="width: 100%; margin-top: 20px;" id="mainBtn" onclick="downloadAll()">下载文件</button>
        <button class="btn btn-secondary" style="width: 100%; margin-top: 10px; display: none;" id="zipBtn" onclick="downloadZip()">📦 打包下载 (ZIP)</button>
      </div>
    </div>
  </div>

  <iframe name="dlFrame" style="display: none;"></iframe>
  <div class="toast-container" id="toastContainer"></div>

  <script>
    let shareId = '';
    let requiresPassword = false;
    let shareType = 'file';
    let shareFiles = [];

    async function loadShareInfo() {
      const pathParts = window.location.pathname.split('/');
      shareId = pathParts[pathParts.length - 1];

      if (!shareId) {
        showExpired();
        return;
      }

      try {
        const response = await fetch('/api/share/' + shareId);
        const data = await response.json();

        if (!data.success) {
          showExpired();
          return;
        }

        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('shareContent').style.display = 'block';

        shareType = data.type || 'file';
        shareFiles = data.files || [];
        requiresPassword = !!data.requiresPassword;

        document.getElementById('fileName').textContent = data.fileName;
        const mainBtn = document.getElementById('mainBtn');
        const zipBtn = document.getElementById('zipBtn');

        if (shareType === 'folder') {
          document.getElementById('shareIcon').textContent = '📁';
          document.getElementById('fileSize').textContent = data.fileCount + ' 个文件 · ' + data.fileSizeFormatted;
          mainBtn.style.display = 'none';
          zipBtn.style.display = 'block';
        } else if (shareType === 'multi') {
          document.getElementById('shareIcon').textContent = '🗂️';
          document.getElementById('fileSize').textContent = data.fileCount + ' 个文件 · ' + data.fileSizeFormatted;
          mainBtn.style.display = 'none';
          zipBtn.style.display = 'block';
        } else {
          document.getElementById('fileSize').textContent = data.fileSizeFormatted;
        }

        if (requiresPassword) {
          document.getElementById('passwordForm').style.display = 'block';
        }

        if (shareType !== 'file' && !requiresPassword && shareFiles.length) {
          renderFileList(shareFiles);
        }
      } catch (error) {
        showExpired();
      }
    }

    let fileListShown = false;

    function renderFileList(files) {
      const listView = document.getElementById('fileListView');
      let html = '';
      files.forEach(function(f, i) {
        const displayName = f.path.indexOf('/') >= 0 ? f.path : f.name;
        const inFolder = displayName.indexOf('/') >= 0;
        html += '<div style="display:flex;align-items:center;gap:8px;padding:8px 10px;border-bottom:1px solid var(--border-color, rgba(128,128,128,.15));">' +
          '<span style="flex-shrink:0;">' + (inFolder ? '📁' : getFileIconSimple(displayName)) + '</span>' +
          '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + escapeAttr(displayName) + '">' + escapeHtml(displayName) + '</span>' +
          '<span style="flex-shrink:0;color:var(--text-muted);font-size:12px;">' + f.sizeFormatted + '</span>' +
          '<button class="btn btn-sm btn-secondary" style="flex-shrink:0;" onclick="downloadOne(' + i + ')">下载</button>' +
        '</div>';
      });
      if (!html) html = '<div style="padding:14px;color:var(--text-muted);text-align:center;">此分享为空</div>';
      listView.innerHTML = html;
      listView.style.display = 'block';
      fileListShown = true;
    }

    function getFileIconSimple(name) {
      const ext = name.split('.').pop().toLowerCase();
      if (['jpg','jpeg','png','gif','svg','webp','bmp','ico'].indexOf(ext) >= 0) return '🖼️';
      if (['mp3','wav','flac','m4a','ogg','aac'].indexOf(ext) >= 0) return '🎵';
      if (['mp4','avi','mkv','mov','webm','flv'].indexOf(ext) >= 0) return '🎬';
      if (['zip','rar','7z','tar','gz','bz2'].indexOf(ext) >= 0) return '📦';
      if (ext === 'pdf') return '📕';
      if (ext === 'doc' || ext === 'docx') return '📘';
      if (ext === 'xls' || ext === 'xlsx') return '📗';
      return '📄';
    }

    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text == null ? '' : String(text);
      return div.innerHTML;
    }

    function escapeAttr(text) {
      return escapeHtml(text).replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function showExpired() {
      document.getElementById('loadingState').style.display = 'none';
      document.getElementById('expiredState').style.display = 'block';
    }

    function getPassword() {
      const el = document.getElementById('sharePassword');
      return el ? el.value : '';
    }

    async function verifyPasswordIfNeeded() {
      if (!requiresPassword) return true;
      const password = getPassword();
      if (!password) {
        showToast('请输入分享密码', 'error');
        return false;
      }
      try {
        const resp = await fetch('/api/share/' + shareId + '/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: password })
        });
        if (!resp.ok) {
          const data = await resp.json().catch(function() { return {}; });
          showToast(data.message || '密码错误', 'error');
          return false;
        }
        // 验密成功后补拉加密分享的文件清单（info 接口对加密分享不返回 files）
        const vdata = await resp.json().catch(function() { return {}; });
        if (vdata.success && Array.isArray(vdata.files) && shareType !== 'file' && !fileListShown) {
          renderFileList(vdata.files);
        }
        return true;
      } catch (e) {
        showToast('校验失败: ' + e.message, 'error');
        return false;
      }
    }

    // 通过隐藏 iframe + form POST 触发浏览器原生流式下载（不经内存 blob，大文件也不怕）
    function postDownload(action, fields) {
      const form = document.createElement('form');
      form.method = 'POST';
      form.action = action;
      form.target = 'dlFrame';
      form.style.display = 'none';
      Object.keys(fields).forEach(function(k) {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = k;
        input.value = fields[k];
        form.appendChild(input);
      });
      document.body.appendChild(form);
      form.submit();
      setTimeout(function() { form.remove(); }, 60000);
    }

    async function downloadAll() {
      if (!await verifyPasswordIfNeeded()) return;
      if (shareType === 'file') {
        postDownload('/api/share/' + shareId + '/download', { password: getPassword() });
        showToast('下载开始', 'success');
      } else {
        downloadZip();
      }
    }

    async function downloadZip() {
      if (!await verifyPasswordIfNeeded()) return;
      postDownload('/api/share/' + shareId + '/zip', { password: getPassword() });
      showToast('打包下载已开始', 'success');
    }

    async function downloadOne(i) {
      if (!await verifyPasswordIfNeeded()) return;
      const f = shareFiles[i];
      if (!f) return;
      postDownload('/api/share/' + shareId + '/file', { password: getPassword(), path: f.path });
      showToast('已开始下载: ' + f.name, 'success');
    }

    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      container.appendChild(toast);

      setTimeout(() => {
        toast.remove();
      }, 3000);
    }

    // Initialize
    loadShareInfo();
  </script>
</body>
</html>
`;

// ============================================================================
// MAIN REQUEST HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    
    // CORS headers for API requests
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    };
    
    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    try {
      // API Routes
      if (path.startsWith('/api/')) {
        // Auth routes
        if (path === '/api/login' && method === 'POST') {
          return await handleLogin(request, env);
        }

        if (path === '/api/register' && method === 'POST') {
          return await handleRegister(request, env);
        }
        
        if (path === '/api/logout' && method === 'POST') {
          return await handleLogout();
        }
        
        if (path === '/api/auth/check') {
          return await handleCheckAuth(request, env);
        }
        
        // File management routes
        if (path === '/api/files' || path.startsWith('/api/files/') || path.startsWith('/api/files%')) {
          const filePath = safeDecode(path.slice('/api/files'.length)) || '/';
          
          if (method === 'GET') {
            return await handleListFiles(request, env, filePath);
          }
          if (method === 'POST') {
            return await handleUploadFile(request, env, filePath);
          }
          if (method === 'PUT') {
            return await handleRenameFile(request, env, filePath);
          }
          if (method === 'DELETE') {
            return await handleDeleteFile(request, env, filePath);
          }
        }
        
        // Folder creation
        if (path === '/api/folders' && method === 'POST') {
          return await handleCreateFolder(request, env);
        }
        
        // Folder zip download route（必须放在 /api/download 前缀匹配之前）
        if (path === '/api/download-folder' || path.startsWith('/api/download-folder/') || path.startsWith('/api/download-folder%')) {
          const filePath = safeDecode(path.slice('/api/download-folder'.length));
          return await handleDownloadFolder(request, env, filePath);
        }

        // Download route
        if (path === '/api/download' || path.startsWith('/api/download/') || path.startsWith('/api/download%')) {
          const filePath = safeDecode(path.slice('/api/download'.length));
          return await handleDownloadFile(request, env, filePath);
        }
        
        // Preview route
        if (path === '/api/preview' || path.startsWith('/api/preview/') || path.startsWith('/api/preview%')) {
          const filePath = safeDecode(path.slice('/api/preview'.length));
          return await handlePreviewFile(request, env, filePath);
        }
        
        // Share routes
        if (path === '/api/share' && method === 'POST') {
          return await handleCreateShare(request, env);
        }
        
        if (path.match(/^\/api\/share\/[^/]+$/) && method === 'GET') {
          const shareId = path.split('/').pop();
          return await handleGetShareInfo(request, env, shareId);
        }
        
        if (path.match(/^\/api\/share\/[^/]+\/download$/) && method === 'POST') {
          const shareId = path.split('/')[3];
          return await handleShareDownload(request, env, shareId);
        }

        if (path.match(/^\/api\/share\/[^/]+\/verify$/) && method === 'POST') {
          const shareId = path.split('/')[3];
          return await handleShareVerify(request, env, shareId);
        }

        if (path.match(/^\/api\/share\/[^/]+\/file$/) && method === 'POST') {
          const shareId = path.split('/')[3];
          return await handleShareFileDownload(request, env, shareId);
        }

        if (path.match(/^\/api\/share\/[^/]+\/zip$/) && method === 'POST') {
          const shareId = path.split('/')[3];
          return await handleShareZipDownload(request, env, shareId);
        }
        
        // Admin routes
        if (path === '/api/admin/stats' && method === 'GET') {
          return await handleAdminStats(request, env);
        }

        if (path === '/api/admin/shares' && method === 'GET') {
          return await handleListShares(request, env);
        }

        if (path === '/api/admin/shares/batch-delete' && method === 'POST') {
          return await handleBatchDeleteShares(request, env);
        }

        if (path.match(/^\/api\/admin\/shares\/[^/]+$/) && method === 'DELETE') {
          const shareId = path.split('/').pop();
          return await handleDeleteShare(request, env, shareId);
        }
        
        if (path === '/api/admin/users' && method === 'GET') {
          return await handleListUsers(request, env);
        }
        
        if (path === '/api/admin/users' && method === 'POST') {
          return await handleCreateUser(request, env);
        }
        
        if (path.match(/^\/api\/admin\/users\/[^/]+$/) && method === 'PUT') {
          const email = path.split('/').pop();
          return await handleUpdateUser(request, env, email);
        }

        if (path.match(/^\/api\/admin\/users\/[^/]+\/reset-password$/) && method === 'POST') {
          const email = path.split('/').slice(-2, -1).join('/');
          return await handleResetUserPassword(request, env, email);
        }

        if (path === '/api/admin/storage' && method === 'GET') {
          return await handleGetStorage(request, env);
        }

        if (path === '/api/admin/storage' && method === 'PUT') {
          return await handleUpdateStorage(request, env);
        }
        
        if (path.match(/^\/api\/admin\/users\/[^/]+$/) && method === 'DELETE') {
          const email = path.split('/').pop();
          return await handleDeleteUser(request, env, email);
        }
        
        return jsonResponse({ success: false, message: 'API 路径不存在' }, 404);
      }
      
      // Share page route
      if (path.startsWith('/s/')) {
        return htmlResponse(SHARE_PAGE);
      }
      
      // Static page routes
      if (path === '/login.html' || path === '/login') {
        return htmlResponse(LOGIN_PAGE.replace(/__REG_ENABLED__/g, env.REGISTER_ENABLED === 'true' ? '1' : ''));
      }
      
      if (path === '/admin.html' || path === '/admin') {
        // Check if user is admin
        const auth = await verifyAuth(request, env);
        if (!auth || auth.role !== 'admin') {
          return Response.redirect(url.origin + '/login.html', 302);
        }
        return htmlResponse(ADMIN_PAGE);
      }
      
      // Root and index - check auth
      if (path === '/' || path === '/index.html') {
        const auth = await verifyAuth(request, env);
        if (!auth) {
          return Response.redirect(url.origin + '/login.html', 302);
        }
        return htmlResponse(INDEX_PAGE);
      }
      
      // Default: redirect to root
      return Response.redirect(url.origin + '/', 302);
      
    } catch (error) {
      console.error('Error:', error);
      return jsonResponse({ success: false, message: '服务器错误: ' + error.message }, 500);
    }
  }
};
