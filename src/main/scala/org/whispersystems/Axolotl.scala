package org.whispersystems

import java.security._
import java.security.interfaces.ECPublicKey
import java.security.spec.{ECGenParameterSpec, X509EncodedKeySpec}
import javax.crypto.Cipher
import javax.crypto.spec.{IvParameterSpec, SecretKeySpec}

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.whispersystems.util.{Util, Log}

import scala.collection.immutable.HashMap
import scala.language.implicitConversions

object Axolotl {

  def apply(): Proto = {
    // TODO(kudinkin): Make a static option
    Security.addProvider(new BouncyCastleProvider())
    new Proto
  }

  object Proto {
    // Handshake protocol
    class Handshake(
      val identityKey   : ECPublicKey,
      val handshakeKey  : ECPublicKey,
      val ratchetKey    : ECPublicKey) {}

    // Staged Keys
    case class StagedKey(MK: Array[Byte], CK: Array[Byte]) {}
  }

  class Proto {

    import Proto._
    import Util._

    // Implicits
    object implicits {

      implicit class ByteArray(backing: Array[Byte]) {
        def toString(base: Int): String =
          base match {
            case 16 => backing.map(b => "%02X" format b).mkString
            case _  => throw new IllegalArgumentException("Base '%d' isn't allowed" format base)
          }
      }

      implicit def stringToBytes(s: String) : Array[Byte] = s.getBytes("UTF-8")
      implicit def intToBytes   (i: Int)    : Array[Byte] = {
        val bs = new Array[Byte](4)
        for (j <- 0 until 4) {
          bs(3 - j) = ((i >>> (3 - j << 3)) & 0xFF).toByte
        }
        bs
      }

      implicit def intFromBytes (bs: Array[Byte]) : Int = {
        var i = 0
        for (j <- bs.indices) {
          i <<= 8
          i |= bs(bs.length - j - 1) & 0xFF
        }
        i
      }
    }

    import implicits._

    object Role extends Enumeration {
      type Role = Value

      val Alice, Bob = Value
    }

    import Role._

    def open(): SecureChannel = new SecureChannel

    class SecureChannel {

      object Storage {
        def stageSkippedKeys(N: Int, Nr: Int, HKr: Array[Byte], CKr: Array[Byte]): StagedKey = {
          Log.t("STAGE SKIPPED N/Nr/HKr/CKr: ", N, Nr, HKr, CKr)

          var MK : Array[Byte] = null
          var CK = CKr

          for (i <- 0 until N - Nr) {
            MK = HMAC(CK, "0")
            CK = HMAC(CK, "1")

            // TODO(kudinkin): Stage/unstage properly
            state.staged = state.staged + (MK -> HKr)
          }

          new StagedKey(
            MK = HMAC(CK, "0"),
            CK = HMAC(CK, "1")
          )
        }

        def commitSkippedKeys() {
          //throw new NotImplementedError("Implement me!")
        }
      }

      class State(
        val DHI: KeyPair,
        val DHR: KeyPair,
        val DHHS: KeyPair) {

        // Role
        var role: Role = null

        // Root key
        var RK    : Array[Byte] = null

        // Header keys
        var HKs   : Array[Byte] = null
        var HKr   : Array[Byte] = null

        // Next-header keys
        var NHKs  : Array[Byte] = null
        var NHKr  : Array[Byte] = null

        // Chain keys
        var CKs   : Array[Byte] = null
        var CKr   : Array[Byte] = null

        // Ratchet keys
        var DHRs  : KeyPair = null
        var DHRr  : ECPublicKey = null

        // Counters
        var Ns  = 0
        var Nr  = 0
        var PNs = 0

        var staged: Map[Array[Byte], Array[Byte]] = new HashMap[Array[Byte], Array[Byte]]

        // Ratchet flag
        var RF = false

        /* package */ def extend(masterKey: Array[Byte], otherPartyRatchetKey: ECPublicKey) {
          role match {
            case Role.Alice =>
              RK    = PBKDF2(masterKey, "0xDEADBEEF")

              HKs   = PBKDF2(masterKey, "0xDEADBABE")
              HKr   = PBKDF2(masterKey, "0xBABEBEEF")

              NHKs  = PBKDF2(masterKey, "0xDEADC0DE")
              NHKr  = PBKDF2(masterKey, "0xDEADDEAD")

              CKs   = PBKDF2(masterKey, "0xDEADD00D")
              CKr   = PBKDF2(masterKey, "0xDEAD10CC")

              DHRs  = null
              DHRr  = otherPartyRatchetKey

              RF = true

            case Role.Bob =>
              RK    = PBKDF2(masterKey, "0xDEADBEEF")

              HKs   = PBKDF2(masterKey, "0xBABEBEEF")
              HKr   = PBKDF2(masterKey, "0xDEADBABE")

              NHKs  = PBKDF2(masterKey, "0xDEADDEAD")
              NHKr  = PBKDF2(masterKey, "0xDEADC0DE")

              CKs   = PBKDF2(masterKey, "0xDEAD10CC")
              CKr   = PBKDF2(masterKey, "0xDEADD00D")

              DHRs  = state.DHR
              DHRr  = null

              RF = false
          }
        }
      }

      var state: State = new State(generateKeyPair(), generateKeyPair(), generateKeyPair())

      def introduce(): Handshake =
        new Handshake(
          identityKey   = state.DHI   .getPublic.asInstanceOf[ECPublicKey],
          handshakeKey  = state.DHHS  .getPublic.asInstanceOf[ECPublicKey],
          ratchetKey    = state.DHR   .getPublic.asInstanceOf[ECPublicKey]
        )

      def handshake(otherParty: Handshake, authenticate: Boolean) {
        val role = decide(otherParty)

        role match {
          case Alice  => state.role = Alice;
          case Bob    => state.role = Bob;

          case _ =>
            throw new SecurityException("Eve have been caught!")
        }

        val masterKey = tripleDH(state.DHI, state.DHHS, otherParty.identityKey, otherParty.handshakeKey)

        state.extend(masterKey, otherParty.ratchetKey)
      }

      private def generateKeyPair(): KeyPair = {
        val g = KeyPairGenerator.getInstance("ECDH", "BC")

        // TODO(kudinkin): De-fixate private-key
        // TODO(kudinkin): Rail on curve25519
        g.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom("FIXATED".getBytes))
        g.generateKeyPair()
      }

      private def tripleDH(A: KeyPair, A0: KeyPair, B: ECPublicKey, B0: ECPublicKey): Array[Byte] = {
        //
        // A  - our identity key-pair
        // A0 - our hand-shake key-pair
        // B  - their identity public-key
        // B0 - their hand-shake public-key
        //
        // The whole key-agreement scheme:
        // -------------------------------
        //   - Parties exchange identity keys (A, B) and handshake keys (A0, A1) and (B0, B1)
        //   - Parties assign "Alice" and "Bob" roles by comparing public keys
        //   - Parties calculate master key using tripleDH:
        //     - master_key = HASH( DH(A, B0) || DH(A0, B) || DH(A0, B0) )
        //

        val digest = MessageDigest.getInstance("SHA-256")

        state.role match {
          case Alice  => digest.update(DH(A, B0) ++ DH(A0, B) ++ DH(A0, B0))
          case Bob    => digest.update(DH(A0, B) ++ DH(A, B0) ++ DH(A0, B0))
          case _ =>
            throw new SecurityException("Eve have been caught!")
        }

        digest.digest()
      }

      private def decide(otherParty: Handshake): Role = {
        val ownW    = state.DHI.getPublic.asInstanceOf[ECPublicKey].getW
        val otherW  = otherParty.identityKey.getW

        if (ownW.getAffineX.compareTo(otherW.getAffineX) < 0) Alice else Bob
      }

      def encryptMessage(payload: Array[Byte]): Array[Byte] = {

        Log.v(">> [x] ENCRYPT: BEGIN >>>>>>>>>>>>>>>")

        var ratcheting = false

        // Ratchet
        if (state.RF) {

          Log.t(">> [x] RATCHET: BEGIN")

          ratcheting = true

          state.DHRs = generateKeyPair()

          state.PNs = state.Ns
          state.Ns = 0

          state.HKs = state.NHKs

          Log.t(">> [x] ROOT KEY PBKDF: BEGIN")

          state.RK = PBKDF2(HMAC(state.RK, DH(state.DHRs, state.DHRr)), "0xDEADBEEF")

          Log.t(">> [x] ROOT KEY PBKDF: END")

          state.role match {
            case Alice =>
              state.NHKs  = PBKDF2(state.RK, "0xDEADC0DE")
              state.CKs   = PBKDF2(state.RK, "0xDEADD00D")
            case Bob =>
              state.NHKs  = PBKDF2(state.RK, "0xDEADDEAD")
              state.CKs   = PBKDF2(state.RK, "0xDEAD10CC")
          }

          state.RF = false
        }

        Log.t(">> [x] RATCHET: END")

        val header_key = state.HKs
        val message_key = HMAC(state.CKs, "0")

        // TODO(kudinkin): Extract
        val HEADER_LENGTH = 106

        var header = new Array[Byte](HEADER_LENGTH)

        header = emplace(header, 0, state.Ns, 0, 3)
        header = emplace(header, 3, state.PNs, 0, 3)

        var header_len = 6

        if (ratcheting) {
          val ratchet_key = marshallRatchetKey(state.DHRs)
          header = emplace(header, 6, ratchet_key, 0, 100)
          header_len += ratchet_key.length
        }

        val pad_len = HEADER_LENGTH - header_len
        val pad = PRNG.randomBytes(pad_len - 1)

        // Pad header to have `HEADER_LENGTH` long
        header = emplace(header, header_len, pad, 0, 100)
        header = emplace(header, 105, pad_len, 0, 1)

        val body = encrypt(payload, message_key)

        state.Ns += 1
        state.CKs = HMAC(state.CKs, "1")

        Log.v(">> [x] ENCRYPT: END >>>>>>>>>>>>>>>")

        header ++ body
      }

      def decryptMessage(bytes: Array[Byte]): Array[Byte] = {
        Log.v(">> [x] DECRYPT: BEGIN >>>>>>>>>>>>>>>")

        val padding = bytes.slice(105, 106)(0); // < 106

        Log.t(">> [x] PADDING: ", padding)

        val header = bytes.slice(0, 106 - padding)
        val body = bytes.slice(106, bytes.length)

        // Probe already seen message-keys
        //val decrypted = Storage.probeSkippedKeys(bytes, padding)

        val decrypted = new {
          var header: Array[Byte] = null
          var body: Array[Byte] = null
        }

        if (decrypted.body != null && decrypted.header != null)
          return decrypted.body

        // Probe current header-key
        decrypted.header = header; //self._decrypt(header, self.state.HKr);

        var DHRp  : ECPublicKey = null  // Purported DHR
        var Np    : Int = -1            // Purported message number

        Np = header.slice(0, 3)

        if (header.length == 6)
          DHRp = null
        else
          DHRp = unmarshalRatchetKey(decrypted.header.slice(6, decrypted.header.length))

        // Check whether any ratcheting session is in progress
        if (DHRp == null) {

          // Preserve missing message-keys for messages arriving out-of-order,
          // and derive keys for the current message
          val next = Storage.stageSkippedKeys(Np, state.Nr, state.HKr, state.CKr)

          decrypted.body = decrypt(body, next.MK)

          if (decrypted.body == null)
            throw new SecurityException("Undecipherable!")

          state.CKr = next.CK

        } else {

          // Probe next header-key
          //decrypted.header = self._decrypt(header, self.state.NHKr);

          if (state.RF) {
            throw new IllegalStateException("Other ratcheting-session is in-progress! [" + state.role + "]")
          }

          if (decrypted.header == null)
            throw new SecurityException("Undecipherable!")

          // Next header-key involvement designates other-party having completed
          // the ratchet round

          var PNp: Int = -1 // Purported previous message number

          PNp = decrypted.header.slice(3, 6)

          // _DBG
          Log.t(">> Np: ", Np)
          Log.t(">> PNp: ", PNp)

          // Stage already skipped message keys
          Storage.stageSkippedKeys(PNp, state.Nr, state.HKr, state.CKr)

          Log.t(">> [x] RATCHET: BEGIN")
          Log.t(">> [x] ROOT KEY PBKDF: BEGIN")

          val RKp = PBKDF2(HMAC(state.RK, DH(state.DHRs, DHRp).toString(16)), "0xDEADBEEF")

          Log.t(">> [x] ROOT KEY PBKDF: END")
          Log.t(">> [x] RATCHET: END")

          val HKp = state.NHKr

          var NHKp  : Array[Byte] = null
          var CKp   : Array[Byte] = null

          state.role match {
            case Role.Alice =>
              NHKp  = PBKDF2(RKp, "0xDEADDEAD")
              CKp   = PBKDF2(RKp, "0xDEAD10CC")

            case Role.Bob =>
              NHKp  = PBKDF2(RKp, "0xDEADC0DE")
              CKp   = PBKDF2(RKp, "0xDEADD00D")

            case _ =>
              throw new SecurityException("Eve has been catched right away!")
          }

          // Restore skipped keys from the new ratchet-session
          val keys = Storage.stageSkippedKeys(Np, 0, HKp, CKp)

          decrypted.body = decrypt(body, keys.MK)

          state.CKr   = keys.CK

          state.RK    = RKp
          state.HKr   = HKp
          state.NHKr  = NHKp
          state.DHRr  = DHRp

          state.RF = true
        }

        // Commit skipped header-/message- keys to persistent storage
        Storage.commitSkippedKeys()

        state.Nr = Np + 1

        // _DBG
        Log.v(">> [x] DECRYPT: END >>>>>>>>>>>>>>>")

        return decrypted.body

        // TODO(kudinkin): Decrypt headers to support V2 and ratcheting

        //var message_key = self.HMAC(self.state.CKr, "0");

        //  var decrypted = self._decrypt(bytes, message_key);
        //
        //  self.state.Ns += 1;
        //  self.state.CKs = self.HMAC(self.state.CKs, "1");
        //
        //  return decrypted;
      }

      private def encrypt(payload: Array[Byte], key: Array[Byte]): Array[Byte] = {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(PRNG.randomBytes(16)))

        val params = cipher.getParameters

        val iv = params.getParameterSpec(classOf[IvParameterSpec]).getIV
        val cipherText = cipher.doFinal(payload)

        iv ++ cipherText
      }

      private def decrypt(bytes: Array[Byte], key: Array[Byte]): Array[Byte] = {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        val (iv, cipherText) = bytes.splitAt(16)

        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv))
        cipher.doFinal(cipherText)
      }

    }

    private def unmarshalRatchetKey(bytes: Array[Byte]): ECPublicKey = {
      KeyFactory.getInstance("ECDH", "BC").generatePublic(new X509EncodedKeySpec(bytes)).asInstanceOf[ECPublicKey]
    }

    private def marshallRatchetKey(ratchetKey: KeyPair): Array[Byte] = ratchetKey.getPublic.getEncoded
  }
}