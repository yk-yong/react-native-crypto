import {
  hmacSha256,
  sha1,
  sha256,
  tripleDesDecrypt,
  tripleDesEncrypt,
} from '@yk-yong/react-native-crypto';
import { useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';

const helloWorldHashBase64 = '3/1gIbsr1bCvZ2KQgJ7DpTGR3YHH9wpLKGiKNiGCmG8=';
const helloWorldSha1Base64 = 'CgqfKmdylCVXq1NV12r0Qvj2XgE=';
const helloWorldHmacSha256Base64 =
  'Fu5SX2yUT/SaNozVk+t7cog7FEVse1g7uk/5c/9LMPk=';

export default function App() {
  const [hash, setHash] = useState<string>('');
  const [hashSha1, setHashSha1] = useState<string>('');
  const [hmac, setHmac] = useState<string>('');
  const [tripleDesResult, setTripleDesResult] = useState<string>('');

  useEffect(() => {
    async function computeHash() {
      const result = await sha256('Hello, World!');
      setHash(result);
    }
    computeHash();
  }, []);

  useEffect(() => {
    async function computeHashSha1() {
      const result = await sha1('Hello, World!');
      setHashSha1(result);
    }
    computeHashSha1();
  }, []);

  useEffect(() => {
    async function computeHmac() {
      // Example HMAC computation (using sha256 as the hash function)
      const key = 'secret-key';
      const message = 'Hello, World!';
      const hmacResult = await hmacSha256(key, message);
      setHmac(hmacResult);
    }
    computeHmac();
  }, []);

  useEffect(() => {
    async function computeTripleDes() {
      try {
        const key = '47c4fa1fdcca1360d5e5382ba1073ab7c24ca587aab49775'; // 24-byte key for TripleDES
        const data = 'Hello, World!';
        const encryptedData = await tripleDesEncrypt(key, data);
        const decryptedData = await tripleDesDecrypt(key, encryptedData);

        setTripleDesResult(decryptedData);
      } catch (error) {
        console.log('TripleDES Error:', error);
      }
    }
    computeTripleDes();
  }, []);

  return (
    <View style={styles.container}>
      <Text>
        {hash === helloWorldHashBase64
          ? 'SHA256 is valid!'
          : 'SHA256 is invalid.'}
      </Text>
      <Text>
        {hashSha1 === helloWorldSha1Base64
          ? ' SHA1 is valid!'
          : ' SHA1 is invalid.'}
      </Text>
      <Text>
        {hmac === helloWorldHmacSha256Base64
          ? ' HMAC-SHA256 is valid!'
          : ' HMAC-SHA256 is invalid.'}
      </Text>
      <Text>
        {tripleDesResult === 'Hello, World!'
          ? ' TripleDES encryption/decryption is valid!'
          : ' TripleDES encryption/decryption is invalid.'}
      </Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
});
