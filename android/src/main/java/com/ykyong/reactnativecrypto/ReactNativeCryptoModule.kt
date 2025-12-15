package com.ykyong.reactnativecrypto

import android.util.Base64
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.module.annotations.ReactModule
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

@ReactModule(name = ReactNativeCryptoModule.NAME)
class ReactNativeCryptoModule(reactContext: ReactApplicationContext) :
  NativeReactNativeCryptoSpec(reactContext) {

  private val TRANSFORMATION = "Desede/ECB/PKCS5Padding"
  private val ALGORITHM = "DESede"

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
      val keySpec = getKeySpec(key)

      val cipher = Cipher.getInstance(TRANSFORMATION)
      // ECB mode does NOT use an IV, so we only pass the mode and key
      cipher.init(Cipher.ENCRYPT_MODE, keySpec)

      val plainBytes = data.toByteArray(Charsets.UTF_8)
      val cipherText = cipher.doFinal(plainBytes)

      val result = Base64.encodeToString(cipherText, Base64.NO_WRAP)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("ENCRYPTION_ERROR", "Triple DES encryption failed: ${e.message}", e)
    }
  }

  override fun tripleDesDecrypt(key: String, encryptedData: String, promise: Promise): Unit {
    try {
      val keySpec = getKeySpec(key)

      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.DECRYPT_MODE, keySpec)

      val encryptedBytes = Base64.decode(encryptedData, Base64.DEFAULT)
      val plainBytes = cipher.doFinal(encryptedBytes)

      val result = String(plainBytes, Charsets.UTF_8)
      promise.resolve(result)
    } catch (e: Exception) {
      promise.reject("DECRYPTION_ERROR", "Triple DES decryption failed: ${e.message}", e)
    }
  }

  private fun getKeySpec(key: String): SecretKeySpec {
    var keyBytes = key.toByteArray(Charsets.UTF_8)

    // Case 1: Key is already 24 bytes. Perfect.
    if (keyBytes.size == 24) {
      return SecretKeySpec(keyBytes, ALGORITHM)
    }

    // Case 2: Key is 16 bytes (Common in CryptoJS).
    // We must mimic "2-Key Triple DES" by copying the first 8 bytes to the end.
    // K1 (8) + K2 (8) -> K1 (8) + K2 (8) + K1 (8)
    if (keyBytes.size == 16) {
      val key24Bytes = ByteArray(24)
      System.arraycopy(keyBytes, 0, key24Bytes, 0, 16)       // Copy first 16 bytes
      System.arraycopy(keyBytes, 0, key24Bytes, 16, 8)       // Repeat first 8 bytes at the end
      return SecretKeySpec(key24Bytes, ALGORITHM)
    }

    // Case 3: Any other length (Short or Long) -> Fallback to Zero Padding or Truncation
    // This is a safety catch-all.
    val key24Bytes = ByteArray(24)
    val lengthToCopy = if (keyBytes.size > 24) 24 else keyBytes.size
    System.arraycopy(keyBytes, 0, key24Bytes, 0, lengthToCopy)
    return SecretKeySpec(key24Bytes, ALGORITHM)
  }

  companion object {
    const val NAME = "ReactNativeCrypto"
  }
}
