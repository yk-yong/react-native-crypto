package com.ykyong.reactnativecrypto

import android.util.Base64
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

  override fun sha256(input: String): String {
    val bytes = input.toByteArray(Charsets.UTF_8)
    val digest = MessageDigest.getInstance("SHA-256")
    val hashBytes = digest.digest(bytes)
    return Base64.encodeToString(hashBytes, Base64.NO_WRAP)
  }

  override fun sha1(input: String): String {
    val bytes = input.toByteArray(Charsets.UTF_8)
    val digest = MessageDigest.getInstance("SHA-1")
    val hashBytes = digest.digest(bytes)
    return Base64.encodeToString(hashBytes, Base64.NO_WRAP)
  }

  override fun hmacSha256(key: String, data: String): String {
    val sha256Hmac = Mac.getInstance("HmacSHA256")
    val secretKey = SecretKeySpec(key.toByteArray(Charsets.UTF_8), "HmacSHA256")
    sha256Hmac.init(secretKey)
    val hashBytes = sha256Hmac.doFinal(data.toByteArray(Charsets.UTF_8))
    return Base64.encodeToString(hashBytes, Base64.NO_WRAP)
  }

  override fun convertHashEncoding(hash: String, from: String, to: String): String {
    val bytes = when (from) {
      "hex" -> hexToBytes(hash)
      "base64" -> Base64.decode(hash, Base64.DEFAULT)
      else -> throw IllegalArgumentException("Invalid 'from' encoding. Must be 'hex' or 'base64'.")
    }

    return when (to) {
      "hex" -> bytes.joinToString("") { "%02x".format(it) }
      "base64" -> Base64.encodeToString(bytes, Base64.NO_WRAP)
      else -> throw IllegalArgumentException("Invalid 'to' encoding. Must be 'hex' or 'base64'.")
    }
  }

  companion object {
    const val NAME = "ReactNativeCrypto"
  }
}
