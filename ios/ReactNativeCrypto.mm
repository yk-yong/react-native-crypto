#import "ReactNativeCrypto.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>

@implementation ReactNativeCrypto

// Helper method to convert hex string to NSData
- (NSData *)hexStringToData:(NSString *)hexString {
    NSMutableData *data = [NSMutableData data];
    unsigned int hexValue;
    for (NSUInteger i = 0; i < hexString.length; i += 2) {
        NSString *hexByte = [hexString substringWithRange:NSMakeRange(i, 2)];
        if ([[NSScanner scannerWithString:hexByte] scanHexInt:&hexValue]) {
            unsigned char byte = (unsigned char)hexValue;
            [data appendBytes:&byte length:1];
        }
    }
    return data;
}

// Helper method to convert NSData to hex string
- (NSString *)dataToHexString:(NSData *)data {
    const unsigned char *bytes = (const unsigned char *)data.bytes;
    NSMutableString *hexString = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; i++) {
        [hexString appendFormat:@"%02x", bytes[i]];
    }
    return hexString;
}

- (void)sha256:(NSString *)message
       resolve:(RCTPromiseResolveBlock)resolve
        reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, hash);

        NSData *hashData = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
        NSString *result = [hashData base64EncodedStringWithOptions:0];
        resolve(result);
    } @catch (NSException *exception) {
        reject(@"SHA256_ERROR", exception.reason, nil);
    }
}

- (void)sha1:(NSString *)message
     resolve:(RCTPromiseResolveBlock)resolve
      reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
        unsigned char hash[CC_SHA1_DIGEST_LENGTH];
        CC_SHA1(data.bytes, (CC_LONG)data.length, hash);

        NSData *hashData = [NSData dataWithBytes:hash length:CC_SHA1_DIGEST_LENGTH];
        NSString *result = [hashData base64EncodedStringWithOptions:0];
        resolve(result);
    } @catch (NSException *exception) {
        reject(@"SHA1_ERROR", exception.reason, nil);
    }
}

- (void)hmacSha256:(NSString *)key
           message:(NSString *)message
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
        NSData *messageData = [message dataUsingEncoding:NSUTF8StringEncoding];

        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA256, keyData.bytes, keyData.length, messageData.bytes, messageData.length, hash);

        NSData *hashData = [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
        NSString *result = [hashData base64EncodedStringWithOptions:0];
        resolve(result);
    } @catch (NSException *exception) {
        reject(@"HMAC_SHA256_ERROR", exception.reason, nil);
    }
}

- (void)convertHashEncoding:(NSString *)hash
               fromEncoding:(NSString *)fromEncoding
                 toEncoding:(NSString *)toEncoding
                    resolve:(RCTPromiseResolveBlock)resolve
                     reject:(RCTPromiseRejectBlock)reject {
    @try {
        NSData *data;

        // Decode from source encoding
        if ([fromEncoding isEqualToString:@"hex"]) {
            data = [self hexStringToData:hash];
        } else if ([fromEncoding isEqualToString:@"base64"]) {
            data = [[NSData alloc] initWithBase64EncodedString:hash options:0];
        } else {
            reject(@"INVALID_ENCODING", @"Invalid 'from' encoding. Must be 'hex' or 'base64'.", nil);
            return;
        }

        // Encode to target encoding
        NSString *result;
        if ([toEncoding isEqualToString:@"hex"]) {
            result = [self dataToHexString:data];
        } else if ([toEncoding isEqualToString:@"base64"]) {
            result = [data base64EncodedStringWithOptions:0];
        } else {
            reject(@"INVALID_ENCODING", @"Invalid 'to' encoding. Must be 'hex' or 'base64'.", nil);
            return;
        }

        resolve(result);
    } @catch (NSException *exception) {
        reject(@"CONVERSION_ERROR", exception.reason, nil);
    }
}

- (void)tripleDesEncrypt:(NSString *)key
                    data:(NSString *)data
                 resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject {
    @try {
        // Decode the key from base64 or hex
        NSData *keyData;
        if (key.length == 48) {
            keyData = [self hexStringToData:key];
        } else {
            keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
        }

        // Ensure key is 24 bytes (192 bits) for 3DES
        if (keyData.length != 24) {
            reject(@"INVALID_KEY", @"Key must be 24 bytes (192 bits) for Triple DES", nil);
            return;
        }

        NSData *dataToEncrypt = [data dataUsingEncoding:NSUTF8StringEncoding];
        size_t bufferSize = dataToEncrypt.length + kCCBlockSize3DES;
        void *buffer = malloc(bufferSize);

        size_t numBytesEncrypted = 0;
        CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                             kCCAlgorithm3DES,
                                             kCCOptionPKCS7Padding,
                                             keyData.bytes,
                                             keyData.length,
                                             nil,
                                             dataToEncrypt.bytes,
                                             dataToEncrypt.length,
                                             buffer,
                                             bufferSize,
                                             &numBytesEncrypted);

        if (cryptStatus == kCCSuccess) {
            NSData *encryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
            NSString *result = [encryptedData base64EncodedStringWithOptions:0];
            resolve(result);
        } else {
            free(buffer);
            reject(@"ENCRYPTION_ERROR", [NSString stringWithFormat:@"Triple DES encryption failed with status: %d", cryptStatus], nil);
        }
    } @catch (NSException *exception) {
        reject(@"ENCRYPTION_ERROR", [NSString stringWithFormat:@"Triple DES encryption failed: %@", exception.reason], nil);
    }
}

- (void)tripleDesDecrypt:(NSString *)key
           encryptedData:(NSString *)encryptedData
                 resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject {
    @try {
        // Decode the key from base64 or hex
        NSData *keyData;
        if (key.length == 48) {
            keyData = [self hexStringToData:key];
        } else {
            keyData = [[NSData alloc] initWithBase64EncodedString:key options:0];
        }

        // Ensure key is 24 bytes (192 bits) for 3DES
        if (keyData.length != 24) {
            reject(@"INVALID_KEY", @"Key must be 24 bytes (192 bits) for Triple DES", nil);
            return;
        }

        NSData *dataToDecrypt = [[NSData alloc] initWithBase64EncodedString:encryptedData options:0];
        size_t bufferSize = dataToDecrypt.length + kCCBlockSize3DES;
        void *buffer = malloc(bufferSize);

        size_t numBytesDecrypted = 0;
        CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                             kCCAlgorithm3DES,
                                             kCCOptionPKCS7Padding,
                                             keyData.bytes,
                                             keyData.length,
                                             nil,
                                             dataToDecrypt.bytes,
                                             dataToDecrypt.length,
                                             buffer,
                                             bufferSize,
                                             &numBytesDecrypted);

        if (cryptStatus == kCCSuccess) {
            NSData *decryptedData = [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
            NSString *result = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
            resolve(result);
        } else {
            free(buffer);
            reject(@"DECRYPTION_ERROR", [NSString stringWithFormat:@"Triple DES decryption failed with status: %d", cryptStatus], nil);
        }
    } @catch (NSException *exception) {
        reject(@"DECRYPTION_ERROR", [NSString stringWithFormat:@"Triple DES decryption failed: %@", exception.reason], nil);
    }
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeReactNativeCryptoSpecJSI>(params);
}

+ (NSString *)moduleName
{
  return @"ReactNativeCrypto";
}

@end
