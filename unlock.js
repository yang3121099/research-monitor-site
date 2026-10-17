'use strict';
(() => {
  const VERSION = 'private-monitor-envelope-v1';
  const AAD = 'private-monitor:dashboard:v1';
  const ITERATIONS = 600000;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const gate = document.getElementById('gate');
  const workspace = document.getElementById('workspace');
  const form = document.getElementById('unlock-form');
  const passwordInput = document.getElementById('password');
  const unlockButton = document.getElementById('unlock-button');
  const revealButton = document.getElementById('show-password');
  const status = document.getElementById('status');
  const iframe = document.getElementById('dashboard');
  let busy = false;
  let unlockGeneration = 0;

  function message(text, error = false) {
    status.textContent = text;
    status.dataset.error = String(error);
  }
  function decodeBase64(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) throw new Error('Invalid encoding');
    return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
  }
  function clearPassword() {
    passwordInput.value = '';
    passwordInput.type = 'password';
    revealButton.textContent = '显示';
    revealButton.setAttribute('aria-label', '显示密码');
    revealButton.setAttribute('aria-pressed', 'false');
  }
  function lock() {
    unlockGeneration += 1;
    // Removing srcdoc destroys the decrypted document and its sandbox context.
    iframe.removeAttribute('srcdoc');
    iframe.src = 'about:blank';
    workspace.hidden = true;
    gate.hidden = false;
    clearPassword();
    message('页面已锁定。');
    passwordInput.focus();
  }
  revealButton.addEventListener('click', () => {
    const visible = passwordInput.type === 'password';
    passwordInput.type = visible ? 'text' : 'password';
    revealButton.textContent = visible ? '隐藏' : '显示';
    revealButton.setAttribute('aria-label', visible ? '隐藏密码' : '显示密码');
    revealButton.setAttribute('aria-pressed', String(visible));
  });
  document.getElementById('lock-button').addEventListener('click', lock);
  // A browser back/forward cache must not restore an unlocked view.
  window.addEventListener('pagehide', lock);
  window.addEventListener('pageshow', (event) => { if (event.persisted) lock(); });
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (busy) return;
    if (!window.isSecureContext || !window.crypto?.subtle) {
      message('此浏览器不支持安全解密。请使用最新版浏览器通过 HTTPS 打开。', true);
      return;
    }
    let password = passwordInput.value.trim();
    if (!password) { passwordInput.focus(); return; }
    const generation = ++unlockGeneration;
    busy = true;
    unlockButton.disabled = true;
    message('正在本机解密…');
    let passwordBytes;
    let plaintext;
    try {
      const response = await fetch('./payload.json', { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' });
      if (!response.ok) throw new Error('Encrypted file unavailable');
      const payload = await response.json();
      if (payload.version !== VERSION || payload.cipher !== 'AES-256-GCM' || payload.aad !== AAD ||
          payload.kdf?.name !== 'PBKDF2' || payload.kdf.hash !== 'SHA-256' || payload.kdf.iterations !== ITERATIONS) {
        throw new Error('Unsupported encrypted file');
      }
      const salt = decodeBase64(payload.kdf.salt);
      const iv = decodeBase64(payload.iv);
      const ciphertext = decodeBase64(payload.ciphertext);
      if (salt.length !== 32 || iv.length !== 12 || ciphertext.length < 17) throw new Error('Invalid encrypted file');
      passwordBytes = encoder.encode(password);
      password = '';
      clearPassword();
      const material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
      passwordBytes.fill(0);
      const key = await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
        material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
      plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: encoder.encode(AAD), tagLength: 128 }, key, ciphertext);
      if (generation !== unlockGeneration) return;
      iframe.removeAttribute('src');
      iframe.srcdoc = decoder.decode(plaintext);
      gate.hidden = true;
      workspace.hidden = false;
      message('');
      document.getElementById('lock-button').focus();
    } catch (_) {
      if (generation === unlockGeneration) {
        clearPassword();
        message('无法解锁：请核对密码，或确认页面文件完整后重试。', true);
        passwordInput.focus();
      }
    } finally {
      password = '';
      passwordBytes?.fill(0);
      if (plaintext) new Uint8Array(plaintext).fill(0);
      busy = false;
      unlockButton.disabled = false;
    }
  });
})();
