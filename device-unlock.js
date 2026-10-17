import { readDeviceKey, siteScope } from './device-key-store.js';
import { DEVICE_ENVELOPE_VERSION, contentAAD, wrappingLabel } from './device-protocol.js';
const gate = document.getElementById('gate');
const workspace = document.getElementById('workspace');
const status = document.getElementById('status');
const retry = document.getElementById('retry-button');
const identity = document.getElementById('key-identity');
const iframe = document.getElementById('dashboard');
const encoder = new TextEncoder();
let busy = false, generation = 0;
function message(value, error = false) { status.textContent = value; status.dataset.error = String(error); }
function decode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new Error('授权文件编码无效。');
  return Uint8Array.from(atob(value), char => char.charCodeAt(0));
}
function lock() {
  generation++;
  iframe.removeAttribute('srcdoc'); iframe.src = 'about:blank';
  workspace.hidden = true; gate.hidden = false; retry.hidden = false;
  message('本次页面已锁定。点击重新检查或刷新可用现有浏览器凭证再次打开。');
}
async function unlock() {
  if (busy) return;
  busy = true; retry.disabled = true; retry.hidden = true;
  const current = ++generation;
  let rawKey, plaintext;
  try {
    if (!window.isSecureContext || !crypto?.subtle || !window.indexedDB) throw new Error('请通过 HTTPS 在支持设备凭证的 Chrome 普通窗口打开。');
    const record = await readDeviceKey();
    if (!record) throw new Error('此浏览器尚无授权凭证。请登记公钥并由管理员批准；本页没有密码或其他回退入口。');
    identity.textContent = '浏览器凭证 ' + record.keyId;
    message('正在使用本浏览器凭证解密…');
    const response = await fetch('./device-payload.json', { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
    if (!response.ok) throw new Error('授权文件暂不可用，请稍后重试。');
    const payload = await response.json();
    const scope = siteScope();
    if (payload.version !== DEVICE_ENVELOPE_VERSION || payload.cipher !== 'AES-256-GCM' || payload.keyWrap !== 'RSA-OAEP-3072-SHA256' ||
        payload.origin !== scope.origin || payload.namespace !== scope.namespace || payload.aad !== contentAAD(scope.origin, scope.namespace) || !Array.isArray(payload.recipients)) throw new Error('授权文件与本站不匹配。');
    const matches = payload.recipients.filter(recipient => recipient?.keyId === record.keyId);
    if (matches.length !== 1) throw new Error('此浏览器凭证尚未加入允许名单。生成公钥本身不会获得访问权限。');
    const iv = decode(payload.iv), ciphertext = decode(payload.ciphertext), wrappedKey = decode(matches[0].wrappedKey);
    if (iv.length !== 12 || ciphertext.length < 17 || wrappedKey.length !== 384) throw new Error('授权文件格式无效。');
    rawKey = await crypto.subtle.decrypt({ name: 'RSA-OAEP', label: encoder.encode(wrappingLabel(scope.origin, scope.namespace, record.keyId)) }, record.privateKey, wrappedKey);
    if (rawKey.byteLength !== 32) throw new Error('授权密钥长度无效。');
    const aesKey = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['decrypt']);
    new Uint8Array(rawKey).fill(0);
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(payload.aad), tagLength: 128 }, aesKey, ciphertext);
    if (current !== generation) return;
    iframe.removeAttribute('src'); iframe.srcdoc = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    gate.hidden = true; workspace.hidden = false; message('');
  } catch (error) {
    if (current === generation) { message(error.name === 'OperationError' ? '本浏览器无法解密此授权文件，请联系管理员核对允许名单和文件完整性。' : error.message || '无法使用本浏览器凭证解锁。', true); retry.hidden = false; }
  } finally {
    if (rawKey) new Uint8Array(rawKey).fill(0);
    if (plaintext) new Uint8Array(plaintext).fill(0);
    busy = false; retry.disabled = false;
  }
}
retry.addEventListener('click', unlock);
document.getElementById('lock-button').addEventListener('click', lock);
window.addEventListener('pagehide', lock);
window.addEventListener('pageshow', event => { if (event.persisted) void unlock(); });
void unlock();
