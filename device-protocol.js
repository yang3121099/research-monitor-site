export const DEVICE_ENVELOPE_VERSION = 'private-monitor-device-envelope-v1';
export const DEVICE_ALLOWLIST_SCHEMA = 'private-monitor-device-allowlist-v1';
export function contentAAD(origin, namespace) {
  return JSON.stringify(['private-monitor:dashboard:device:v1', origin, namespace]);
}
export function wrappingLabel(origin, namespace, keyId) {
  return JSON.stringify(['private-monitor:keywrap:device:v1', origin, namespace, keyId]);
}
