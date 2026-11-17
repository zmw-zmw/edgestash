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

// 页面已迁到 R2 的 __pages__/ 前缀（独立顶层前缀，不属于任何用户 scope，不会出现在文件列表）。
// 目的：把 ~176KB 内联 HTML 从 Worker 模块里剥离，避免冷启动求值超 CPU 预算导致 504。
const PAGE_CACHE = Object.create(null);
async function loadPage(env, key) {
  if (PAGE_CACHE[key] !== undefined) return PAGE_CACHE[key];
  let html = '';
  try {
    const obj = await env.R2_BUCKET.get('__pages__/' + key);
    if (obj) html = await obj.text();
  } catch (e) {
    console.error('loadPage failed:', key, e && e.message);
  }
  if (!html) html = '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>EdgeStash</title></head><body style="font-family:system-ui;padding:40px">页面加载失败，请刷新重试。</body></html>';
  PAGE_CACHE[key] = html;
  return html;
}

// ============ URL 抓取（合并自 mod-mirror）============
// 把外部 https 链接由 Cloudflare 边缘代抓，直接落进用户自己的网盘目录。
// 复用 EdgeStash 的 JWT 鉴权 / 用户隔离前缀 / 配额体系，抓完的文件与上传文件同等对待（可分享、可预览）。
const GRAB_UA = 'drop-welkin/1.0';
const GRAB_BUFFER_LIMIT = 100 * 1024 * 1024;

function grabValidateTarget(searchParams) {
  const target = searchParams.get('url');
  if (!target) throw { status: 400, message: '缺少 url 参数' };
  let tu;
  try { tu = new URL(target); } catch (e) { throw { status: 400, message: 'URL 格式不对' }; }
  if (tu.protocol !== 'https:') throw { status: 400, message: '只支持 https 链接' };
  const h = String(tu.hostname || '').toLowerCase();
  if (!h || h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal') || h.endsWith('.home.arpa')) {
    throw { status: 403, message: '这个地址不允许抓取' };
  }
  if (/^(127\.|10\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(h)) {
    throw { status: 403, message: '这个地址不允许抓取' };
  }
  if (h === '::1' || h === '::' || h.startsWith('fe80:') || h.startsWith('fc') || h.startsWith('fd')) {
    throw { status: 403, message: '这个地址不允许抓取' };
  }
  let name = searchParams.get('name') || '';
  if (!name) name = decodeURIComponent((tu.pathname.split('/').pop() || '')) || '';
  if (!/[\p{L}\p{N}]/u.test(name)) throw { status: 400, message: '无法从链接判断文件名，请手动填写 name 参数' };
  name = name.replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').slice(0, 120).trim();
  if (!name) throw { status: 400, message: '文件名不合法' };
  return { target, name };
}

async function grabOpenUpstream(target) {
  let resp;
  try {
    resp = await fetch(target, { headers: { 'user-agent': GRAB_UA } });
  } catch (e) {
    throw { status: 502, message: '连不上上游：' + (e && e.message ? e.message : e) };
  }
  if (!resp.ok || !resp.body) throw { status: 502, message: '上游返回 ' + resp.status };
  return resp;
}

async function handleGrabSSE(url, env, auth, ctx) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc = new TextEncoder();
  const push = (obj) => writer.write(enc.encode('data: ' + JSON.stringify(obj) + '\n\n')).catch(() => {});
  ctx.waitUntil((async () => {
    try {
      const { target, name } = grabValidateTarget(url.searchParams);
      let folder = (url.searchParams.get('folder') || 'grab/').replace(/^\/+/, '');
      folder = folder.split('/').filter(seg => seg && seg !== '.' && seg !== '..').join('/');
      if (folder) folder += '/'; else folder = 'grab/';

      const resp = await grabOpenUpstream(target);
      const total = Number(resp.headers.get('content-length')) || 0;
      const contentType = resp.headers.get('content-type') || 'application/octet-stream';

      // 配额与全局上限（与上传同一套规则）
      const quotaBytes = await getUserQuotaBytes(env, auth.email);
      if (quotaBytes > 0 && total > 0 && (await getUserUsedBytes(env, auth.email)) + total > quotaBytes) {
        await push({ error: '存储空间不足：配额 ' + formatFileSize(quotaBytes) + '，本文件 ' + formatFileSize(total) });
        await writer.close(); return;
      }
      const capBytes = await getStorageCapBytes(env);
      if (capBytes > 0 && total > 0 && (await getGlobalUsedBytes(env)) + total > capBytes) {
        await push({ error: '云盘额度不够：已用 ' + formatFileSize(await getGlobalUsedBytes(env)) + ' / 上限 ' + formatFileSize(capBytes) });
        await writer.close(); return;
      }

      const scope = userScope(auth);
      const key = scope + folder + name;
      await push({ start: true, name: name, total: total, path: '/' + folder + name });

      let actualSize = total;
      if (total > 0) {
        const [toR2, toCount] = resp.body.tee();
        const putPromise = env.R2_BUCKET.put(key, toR2, { httpMetadata: { contentType: contentType } });
        const reader = toCount.getReader();
        let received = 0; let last = 0;
        for (;;) {
          const r = await reader.read();
          if (r.done) break;
          received += r.value.length;
          const now = Date.now();
          if (now - last >= 250) {
            last = now;
            await push({ received: received, total: total, percent: Math.min(100, Math.round(received / total * 100)) });
          }
        }
        await putPromise;
        actualSize = received;
      } else {
        const chunks = []; let buffered = 0;
        const reader = resp.body.getReader();
        for (;;) {
          const r = await reader.read();
          if (r.done) break;
          buffered += r.value.length;
          if (buffered > GRAB_BUFFER_LIMIT) {
            await reader.cancel();
            await push({ error: '上游没声明文件大小，且超过 100MB；换一个直接给 content-length 的地址（如 raw.githubusercontent.com）' });
            await writer.close(); return;
          }
          chunks.push(r.value);
        }
        const buf = new Uint8Array(buffered); let off = 0;
        for (const c of chunks) { buf.set(c, off); off += c.length; }
        await env.R2_BUCKET.put(key, buf.buffer, { httpMetadata: { contentType: contentType } });
        await push({ received: buffered, total: buffered, percent: 100 });
        actualSize = buffered;
      }
      await push({ done: true, name: name, path: '/' + folder + name, size: actualSize });
    } catch (e) {
      await push({ error: (e && e.message) ? e.message : '抓取失败' });
    } finally {
      try { await writer.close(); } catch (e) {}
    }
  })());
  return new Response(readable, {
    headers: { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-store', 'x-accel-buffering': 'no' }
  });
}

const GRAB_HTML = "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0, viewport-fit=cover\">\n<meta name=\"robots\" content=\"noindex, nofollow\">\n<title>URL 抓取 - EdgeStash</title>\n<style>\n  :root {\n    --primary: #818cf8;\n    --primary-dark: #6366f1;\n    --primary-light: #a5b4fc;\n    --background: #0a0e1a;\n    --surface: rgba(255, 255, 255, 0.045);\n    --surface-light: rgba(255, 255, 255, 0.09);\n    --border: rgba(255, 255, 255, 0.09);\n    --border-strong: rgba(255, 255, 255, 0.16);\n    --text: #eef2ff;\n    --text-muted: #8b93b0;\n    --danger: #f87171;\n  }\n  * { box-sizing: border-box; margin: 0; padding: 0; }\n  body {\n    background: var(--background);\n    color: var(--text);\n    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;\n    min-height: 100vh;\n    padding: 24px 16px 40px;\n  }\n  .wrap { max-width: 680px; margin: 0 auto; }\n  .page-head { text-align: center; margin-bottom: 22px; animation: fadeUp .35s ease; }\n  .page-head h1 {\n    font-size: 24px; font-weight: 700; margin-bottom: 6px;\n    background: linear-gradient(135deg, #6d7cff 0%, #9d5cff 55%, #2dd4ff 100%);\n    -webkit-background-clip: text; background-clip: text;\n    -webkit-text-fill-color: transparent;\n  }\n  .page-head p { color: var(--text-muted); font-size: 13px; }\n  .card {\n    background: var(--surface);\n    border: 1px solid var(--border);\n    border-radius: 14px;\n    padding: 22px;\n    backdrop-filter: blur(14px);\n    -webkit-backdrop-filter: blur(14px);\n    animation: fadeUp .35s ease;\n  }\n  label { display: block; font-size: 12.5px; color: var(--text-muted); margin: 14px 0 6px; }\n  label:first-of-type { margin-top: 0; }\n  input[type=\"text\"] {\n    width: 100%;\n    padding: 11px 14px;\n    background: var(--surface-light);\n    border: 1px solid var(--border-strong);\n    border-radius: 10px;\n    color: var(--text);\n    font-size: 14px;\n    font-family: inherit;\n    transition: border-color .2s, box-shadow .2s;\n  }\n  input[type=\"text\"]::placeholder { color: rgba(139, 147, 176, 0.55); }\n  input[type=\"text\"]:focus { outline: none; border-color: var(--primary); box-shadow: 0 0 0 3px rgba(129, 140, 248, 0.15); }\n  .btn {\n    display: inline-flex; align-items: center; justify-content: center; gap: 7px;\n    padding: 11px 20px; border: 1px solid transparent; border-radius: 11px;\n    font-size: 14px; font-weight: 600; font-family: inherit;\n    cursor: pointer; text-decoration: none; white-space: nowrap;\n    transition: transform .16s ease, box-shadow .16s ease, opacity .16s ease;\n  }\n  .btn-primary {\n    background: linear-gradient(135deg, #6d7cff 0%, #9d5cff 55%, #2dd4ff 100%);\n    color: #fff; width: 100%; margin-top: 18px;\n    box-shadow: 0 4px 18px rgba(109, 124, 255, 0.28);\n  }\n  .btn-primary:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 6px 22px rgba(109, 124, 255, 0.4); }\n  .btn-primary:disabled { opacity: .55; cursor: not-allowed; transform: none; }\n  .bar {\n    height: 8px; background: rgba(255, 255, 255, 0.06);\n    border: 1px solid var(--border); border-radius: 999px;\n    margin-top: 18px; overflow: hidden;\n  }\n  #fill {\n    height: 100%; width: 0%;\n    background: linear-gradient(90deg, #6d7cff, #9d5cff, #2dd4ff);\n    border-radius: 999px; transition: width .25s ease;\n  }\n  #msg { margin-top: 12px; font-size: 13.5px; color: var(--text-muted); min-height: 18px; }\n  #msg.err { color: var(--danger); }\n  #done { margin-top: 10px; font-size: 13.5px; color: var(--text); }\n  #done a { color: var(--primary-light); }\n  .back { text-align: center; margin-top: 18px; }\n  .back a { color: var(--text-muted); font-size: 13px; text-decoration: none; }\n  .back a:hover { color: var(--primary-light); }\n  @keyframes fadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: none; } }\n</style>\n</head>\n<body>\n<div class=\"wrap\">\n  <div class=\"page-head\">\n    <h1>URL 抓取</h1>\n    <p>Cloudflare 边缘代为抓取外部文件，直接存入你的网盘（可分享、可预览）</p>\n  </div>\n  <div class=\"card\">\n    <label for=\"url\">文件直链（仅支持 https）</label>\n    <input type=\"text\" id=\"url\" placeholder=\"https://github.com/owner/repo/releases/download/...\" autocomplete=\"off\">\n    <label for=\"folder\">存入文件夹（网盘内相对路径）</label>\n    <input type=\"text\" id=\"folder\" value=\"grab/\" autocomplete=\"off\">\n    <label for=\"name\">文件名（可选，默认取链接末段）</label>\n    <input type=\"text\" id=\"name\" placeholder=\"自动识别\" autocomplete=\"off\">\n    <button class=\"btn btn-primary\" id=\"go\">开始抓取</button>\n    <div class=\"bar\"><div id=\"fill\"></div></div>\n    <div id=\"msg\"></div>\n    <div id=\"done\"></div>\n  </div>\n  <div class=\"back\"><a href=\"/\">← 返回网盘</a></div>\n</div>\n<script>\n(async function () {\n  try {\n    const r = await fetch('/api/auth/check');\n    const j = await r.json();\n    if (!j.authenticated) { location.href = '/login.html'; return; }\n  } catch (e) { location.href = '/login.html'; }\n})();\nvar $ = function (id) { return document.getElementById(id); };\n$('go').addEventListener('click', function () {\n  var u = $('url').value.trim();\n  if (!u) { $('msg').textContent = '请填入 URL'; $('msg').className = 'err'; return; }\n  var f = $('folder').value.trim() || 'grab/';\n  var n = $('name').value.trim();\n  $('go').disabled = true;\n  $('fill').style.width = '0%';\n  $('msg').textContent = '连接边缘节点…'; $('msg').className = '';\n  $('done').innerHTML = '';\n  var es = new EventSource('/api/grab?url=' + encodeURIComponent(u) + '&folder=' + encodeURIComponent(f) + (n ? '&name=' + encodeURIComponent(n) : ''));\n  es.onmessage = function (e) {\n    var d; try { d = JSON.parse(e.data); } catch (err) { return; }\n    if (d.error) {\n      $('msg').textContent = '失败：' + d.error; $('msg').className = 'err';\n      $('go').disabled = false; es.close(); return;\n    }\n    if (d.start) { $('msg').textContent = '开始：' + d.name + (d.total ? '（' + (d.total / 1048576).toFixed(1) + ' MB）' : ''); }\n    if (d.percent !== undefined) {\n      $('fill').style.width = (d.percent || 0) + '%';\n      $('msg').textContent = '下载中 ' + (d.percent !== null ? d.percent + '%' : '') + (d.received ? ' ' + (d.received / 1048576).toFixed(1) + ' MB' : '');\n    }\n    if (d.done) {\n      $('fill').style.width = '100%';\n      $('msg').textContent = '完成：' + d.name; $('msg').className = '';\n      $('done').innerHTML = '已存入网盘 ' + d.path + '，<a href=\"/\">返回网盘查看</a>，也可在网盘中生成分享链接';\n      es.close(); $('go').disabled = false;\n    }\n  };\n  es.onerror = function () {\n    if ($('msg').textContent.indexOf('完成') !== 0) { $('msg').textContent = '连接中断'; $('msg').className = 'err'; }\n    es.close(); $('go').disabled = false;\n  };\n});\n</script>\n</body>\n</html>\n";


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
        
        if (path === '/api/grab' && method === 'GET') {
          const auth = await requireAuth(request, env);
          if (auth instanceof Response) return auth;
          return await handleGrabSSE(url, env, auth, ctx);
        }
        return jsonResponse({ success: false, message: 'API 路径不存在' }, 404);
      }
      
      // Share page route
      if (path.startsWith('/s/')) {
        return htmlResponse(await loadPage(env, 'share.html'));
      }
      
      // Static page routes
      if (path === '/login.html' || path === '/login') {
        return htmlResponse((await loadPage(env, 'login.html')).replace(/__REG_ENABLED__/g, env.REGISTER_ENABLED === 'true' ? '1' : ''));
      }
      
      if (path === '/admin.html' || path === '/admin') {
        // Check if user is admin
        const auth = await verifyAuth(request, env);
        if (!auth || auth.role !== 'admin') {
          return Response.redirect(url.origin + '/login.html', 302);
        }
        return htmlResponse(await loadPage(env, 'admin.html'));
      }
      
      // Root and index - check auth
      if (path === '/' || path === '/index.html') {
        const auth = await verifyAuth(request, env);
        if (!auth) {
          return Response.redirect(url.origin + '/login.html', 302);
        }
        const idxHtml = (await loadPage(env, 'index.html')).replace(
          "<button class=\"btn btn-secondary\" id=\"adminBtn\" style=\"display:none;\" onclick=\"window.location.href='/admin.html'\">管理后台</button>",
          "<button class=\"btn btn-secondary\" onclick=\"window.location.href='/grab.html'\">🌐 URL 抓取</button><button class=\"btn btn-secondary\" id=\"adminBtn\" style=\"display:none;\" onclick=\"window.location.href='/admin.html'\">管理后台</button>"
        );
        return htmlResponse(idxHtml);
      }
      
      if (path === '/grab.html' || path === '/grab') {
        return htmlResponse(GRAB_HTML);
      }
      // Default: redirect to root
      return Response.redirect(url.origin + '/', 302);
      
    } catch (error) {
      console.error('Error:', error);
      return jsonResponse({ success: false, message: '服务器错误: ' + error.message }, 500);
    }
  }
};
