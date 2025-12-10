package com.ykyong.reactnativecrypto

import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

@ReactModule(name = ReactNativeCryptoModule.NAME)
class ReactNativeCryptoModule(reactContext: ReactApplicationContext) :
  NativeReactNativeCryptoSpec(reactContext) {

  override fun getName(): String {
    return NAME
  }

  private fun hexToBytes(hex: String): ByteArray {
    check(hex.length % 2 == 0) { "Must have an even length" }
    return hex.chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
  }

  override fun sha256(message: String, promise: Promise): Unit {
    try {
      val bytes = message.toByteArray(Charsets.UTF_8)
      val digest = MessageDigest.getInstance("SHA-256")
      val hashBytes = digest.digest(bytes)
      val result = Base64.encodeToString(hashBytes, Base64.NO_WRAP)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject(e)
    }
  }

  override fun sha1(message: String, promise: Promise): Unit {
    try {
      val bytes = message.toByteArray(Charsets.UTF_8)
      val digest = MessageDigest.getInstance("SHA-1")
      val hashBytes = digest.digest(bytes)
      val result = Base64.encodeToString(hashBytes, Base64.NO_WRAP)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject(e)
    }
  }

  override fun hmacSha256(key: String, message: String, promise: Promise): Unit {
    try {
      val sha256Hmac = Mac.getInstance("HmacSHA256")
      val secretKey = SecretKeySpec(key.toByteArray(Charsets.UTF_8), "HmacSHA256")
      sha256Hmac.init(secretKey)
      val hashBytes = sha256Hmac.doFinal(message.toByteArray(Charsets.UTF_8))
      val result = Base64.encodeToString(hashBytes, Base64.NO_WRAP)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject(e)
    }
  }

  override fun convertHashEncoding(hash: String, fromEncoding: String, toEncoding: String, promise: Promise): Unit {
    try {
      val bytes = when (fromEncoding) {
        "hex" -> hexToBytes(hash)
        "base64" -> Base64.decode(hash, Base64.DEFAULT)
        else -> throw IllegalArgumentException("Invalid 'from' encoding. Must be 'hex' or 'base64'.")
      }

      val result = when (toEncoding) {
        "hex" -> bytes.joinToString("") { "%02x".format(it) }
        "base64" -> Base64.encodeToString(bytes, Base64.NO_WRAP)
        else -> throw IllegalArgumentException("Invalid 'to' encoding. Must be 'hex' or 'base64'.")
      }

      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject(e)
    }
  }

  override fun tripleDesEncrypt(key: String, data: String, promise: Promise): Unit {
    try {
      // Decode the key from base64 or hex
      val keyBytes = if (key.length == 48) {
        hexToBytes(key)
      } else {
        Base64.decode(key, Base64.DEFAULT)
      }

      // Ensure key is 24 bytes (192 bits) for 3DES
      if (keyBytes.size != 24) {
        throw IllegalArgumentException("Key must be 24 bytes (192 bits) for Triple DES")
      }

      val secretKey = SecretKeySpec(keyBytes, "DESede")
      val cipher = javax.crypto.Cipher.getInstance("DESede/ECB/PKCS5Padding")
      cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey)

      val dataBytes = data.toByteArray(Charsets.UTF_8)
      val encryptedBytes = cipher.doFinal(dataBytes)
      val result = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)

      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("ENCRYPTION_ERROR", "Triple DES encryption failed: ${e.message}", e)
    }
  }

  override fun tripleDesDecrypt(key: String, encryptedData: String, promise: Promise): Unit {
    try {
      // Decode the key from base64 or hex
      val keyBytes = if (key.length == 48) {
        hexToBytes(key)
      } else {
        Base64.decode(key, Base64.DEFAULT)
      }

      // Ensure key is 24 bytes (192 bits) for 3DES
      if (keyBytes.size != 24) {
        throw IllegalArgumentException("Key must be 24 bytes (192 bits) for Triple DES")
      }

      val secretKey = SecretKeySpec(keyBytes, "DESede")
      val cipher = javax.crypto.Cipher.getInstance("DESede/ECB/PKCS5Padding")
      cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey)

      val encryptedBytes = Base64.decode(encryptedData, Base64.DEFAULT)
      val decryptedBytes = cipher.doFinal(encryptedBytes)
      val result = String(decryptedBytes, Charsets.UTF_8)

      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("DECRYPTION_ERROR", "Triple DES decryption failed: ${e.message}", e)
    }
  }

  companion object {
    const val NAME = "ReactNativeCrypto"
  }
}
