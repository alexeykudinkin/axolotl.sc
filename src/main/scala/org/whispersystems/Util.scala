package org.whispersystems

import java.security.interfaces.ECPublicKey
import java.security.{KeyPair, SecureRandom}
import javax.crypto.{KeyAgreement, Mac, SecretKeyFactory}
import javax.crypto.spec.{SecretKeySpec, PBEKeySpec}

object Util {

  // PBKDF2
  object PBKDF2 {
    val rounds  = 2000
    val bytes   = 256

    def apply(payload: Array[Byte], salt: Array[Byte]) =
      SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        .generateSecret(
          new PBEKeySpec(payload.map(_.toChar), salt, rounds, bytes)
        )
        .getEncoded
  }

  // PRNG
  object PRNG {
    private val source = new SecureRandom()

    def randomBytes(len: Int): Array[Byte] = {
      val bs = new Array[Byte](len)
      source.nextBytes(bs)
      bs
    }
  }

  // HMAC-SHA256
  object HMAC {
    def apply(payload: Array[Byte], salt: Array[Byte]) : Array[Byte] = {
      val digest: Mac = Mac.getInstance("HmacSHA256")
      digest.init(new SecretKeySpec(salt, "HmacSHA256"))
      digest.doFinal()
    }
  }

  // Diffie-Hellman key-agreement protocol
  object DH {
    def apply(keyPair: KeyPair, publicKey: ECPublicKey): Array[Byte] = {
      val agreement = KeyAgreement.getInstance("ECDH")

      agreement.init(keyPair.getPrivate)
      agreement.doPhase(publicKey, true)
      agreement.generateSecret()
    }
  }


  def emplace(target: Array[Byte], to: Int, source: Array[Byte], from: Int, length: Int): Array[Byte] = {
    val slice = source.slice(from, from + length)
    target.patch(to, slice, slice.length)
  }
}

