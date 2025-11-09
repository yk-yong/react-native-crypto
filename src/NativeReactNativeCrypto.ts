import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  hmacSha256(key: string, message: string): Promise<string>;
  sha256(message: string): Promise<string>;
  sha1(message: string): Promise<string>;
  convertHashEncoding(
    hash: string,
    fromEncoding: 'hex' | 'base64',
    toEncoding: 'hex' | 'base64'
  ): Promise<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('ReactNativeCrypto');
