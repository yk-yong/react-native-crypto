import ReactNativeCrypto from './NativeReactNativeCrypto';

export function hmacSha256(key: string, message: string): Promise<string> {
  return ReactNativeCrypto.hmacSha256(key, message);
}

export function sha256(message: string): Promise<string> {
  return ReactNativeCrypto.sha256(message);
}

export function sha1(message: string): Promise<string> {
  return ReactNativeCrypto.sha1(message);
}

export function convertHashEncoding(
  hash: string,
  fromEncoding: 'hex' | 'base64',
  toEncoding: 'hex' | 'base64'
): Promise<string> {
  return ReactNativeCrypto.convertHashEncoding(hash, fromEncoding, toEncoding);
}

export function tripleDesEncrypt(key: string, data: string): Promise<string> {
  return ReactNativeCrypto.tripleDesEncrypt(key, data);
}

export function tripleDesDecrypt(
  key: string,
  encryptedData: string
): Promise<string> {
  return ReactNativeCrypto.tripleDesDecrypt(key, encryptedData);
}
