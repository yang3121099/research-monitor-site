import { createDeviceKey, enrollmentFor, readDeviceKey } from './device-key-store.js';
const button = document.getElementById('enroll-button');
const status = document.getElementById('status');
const output = document.getElementById('public-enrollment');
let busy = false;
function message(value, error = false) { status.textContent = value; status.dataset.error = String(error); }
if (!window.isSecureContext || !crypto?.subtle || !window.indexedDB) {
  button.disabled = true; message('此浏览器不支持安全的持久设备凭证。请通过 HTTPS 使用默认 Chrome 普通窗口。', true);
} else {
  readDeviceKey().then(record => { if (record) { button.textContent = '查看已登记的本机公钥'; message('此浏览器已有凭证。查看公钥不会覆盖或更换现有身份。'); } }).catch(error => { button.disabled = true; message(error.message, true); });
}
button.addEventListener('click', async (event) => {
  if (busy || !event.isTrusted) return;
  busy = true; button.disabled = true; message('正在本浏览器创建或读取凭证…');
  try {
    const record = await createDeviceKey();
    output.value = JSON.stringify(await enrollmentFor(record), null, 2);
    document.getElementById('public-section').hidden = false;
    button.textContent = '查看已登记的本机公钥';
    message('凭证已保存。下方仅为公钥信息；尚需管理员加入允许名单。');
  } catch (error) { message(error.message || '登记失败，未获得访问权限。', true); }
  finally { busy = false; button.disabled = false; }
});
