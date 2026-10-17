const RECORD_ID = 'active-device-key';
export const DEVICE_SCHEMA = 'private-monitor-device-enrollment-v1';
export const ALGORITHM = 'RSA-OAEP-3072-SHA256';
export function siteScope() {
  return { origin: location.origin, namespace: new URL('./', location.href).pathname };
}
function databaseName() {
  const { origin, namespace } = siteScope();
  return `private-monitor-device-v1:${origin}:${namespace}`;
}
function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName(), 1);
    request.onupgradeneeded = () => { if (!request.result.objectStoreNames.contains('keys')) request.result.createObjectStore('keys', { keyPath: 'id' }); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('浏览器不能持久保存设备凭证。请使用普通浏览模式并允许本站存储。'));
    request.onblocked = () => reject(new Error('设备凭证存储被其他页面阻塞，请关闭本站其他标签页后重试。'));
  });
}
export function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export async function publicKeyId(jwk) {
  if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || jwk.e !== 'AQAB') throw new Error('设备公钥无效。');
  const input = new TextEncoder().encode(`private-monitor:device-key:v1\0${jwk.n}\0${jwk.e}`);
  return base64url(await crypto.subtle.digest('SHA-256', input));
}
export async function validateRecord(record) {
  if (!record) return null;
  const scope = siteScope();
  const privateKey = record.privateKey, publicKey = record.publicKey;
  if (record.id !== RECORD_ID || record.schema !== DEVICE_SCHEMA || record.origin !== scope.origin || record.namespace !== scope.namespace ||
      !(privateKey instanceof CryptoKey) || privateKey.type !== 'private' || privateKey.extractable !== false ||
      privateKey.algorithm.name !== 'RSA-OAEP' || privateKey.algorithm.modulusLength !== 3072 || privateKey.algorithm.hash.name !== 'SHA-256' ||
      privateKey.usages.length !== 1 || privateKey.usages[0] !== 'decrypt' ||
      !(publicKey instanceof CryptoKey) || publicKey.type !== 'public' || publicKey.algorithm.name !== 'RSA-OAEP' || publicKey.algorithm.modulusLength !== 3072) {
    throw new Error('本站保存的设备凭证不符合要求；不会自动覆盖已有身份。');
  }
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  if (await publicKeyId(jwk) !== record.keyId) throw new Error('设备公钥标识不匹配；不会替换已有身份。');
  return record;
}
export async function readDeviceKey() {
  const db = await openDatabase();
  try {
    const value = await new Promise((resolve, reject) => {
      const transaction = db.transaction('keys', 'readonly');
      const request = transaction.objectStore('keys').get(RECORD_ID);
      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(new Error('无法读取设备凭证。'));
    });
    return await validateRecord(value);
  } finally { db.close(); }
}
export async function createDeviceKey() {
  const existing = await readDeviceKey();
  if (existing) return existing;
  const scope = siteScope();
  const keys = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, false, ['encrypt', 'decrypt']);
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey);
  const record = { id: RECORD_ID, schema: DEVICE_SCHEMA, ...scope, keyId: await publicKeyId(jwk), privateKey: keys.privateKey, publicKey: keys.publicKey, createdAt: new Date().toISOString() };
  const db = await openDatabase();
  let conflict = false;
  try {
    await new Promise((resolve, reject) => {
      const transaction = db.transaction('keys', 'readwrite');
      const request = transaction.objectStore('keys').add(record);
      transaction.oncomplete = resolve;
      request.onerror = () => { conflict = request.error?.name === 'ConstraintError'; };
      transaction.onerror = () => reject(transaction.error || new Error('设备凭证保存失败。'));
      transaction.onabort = () => reject(transaction.error || new Error('设备凭证保存失败。'));
    });
  } catch (error) {
    if (!conflict) throw error;
    // A simultaneous registration never overwrites the first saved identity.
  } finally { db.close(); }
  const saved = await readDeviceKey();
  if (!saved) throw new Error('设备凭证未能持久保存。');
  return saved;
}
export async function enrollmentFor(record) {
  await validateRecord(record);
  return { schema: DEVICE_SCHEMA, origin: record.origin, namespace: record.namespace, algorithm: ALGORITHM, keyId: record.keyId, publicJwk: await crypto.subtle.exportKey('jwk', record.publicKey) };
}
