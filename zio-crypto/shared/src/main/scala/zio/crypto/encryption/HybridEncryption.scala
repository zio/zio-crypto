package zio.crypto.encryption

import java.nio.charset.Charset

import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.{ HybridDecrypt, HybridEncrypt, KeyTemplate => TinkKeyTemplate, KeyTemplates }

import zio._
import zio.crypto.ByteHelpers
import zio.crypto.keyset.{ AsymmetricKeyset, KeyTemplate, PrivateKeyset, PublicKeyset }

sealed trait HybridEncryptionAlgorithm

object HybridEncryptionAlgorithm {
  case object EciesP256HkdfHmacSha256Aes128Gcm           extends HybridEncryptionAlgorithm
  case object EciesP256HkdfHmacSha256Aes128CtrHmacSha256 extends HybridEncryptionAlgorithm

  implicit val template: KeyTemplate[HybridEncryptionAlgorithm] with AsymmetricKeyset[HybridEncryptionAlgorithm] =
    new KeyTemplate[HybridEncryptionAlgorithm] with AsymmetricKeyset[HybridEncryptionAlgorithm] {
      override def getTinkKeyTemplate(a: HybridEncryptionAlgorithm): TinkKeyTemplate =
        a match {
          case HybridEncryptionAlgorithm.EciesP256HkdfHmacSha256Aes128CtrHmacSha256 =>
            KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256")
          case HybridEncryptionAlgorithm.EciesP256HkdfHmacSha256Aes128Gcm           =>
            KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM")
        }
    }
}

trait HybridEncryption {
  type PrivateKey = PrivateKeyset[HybridEncryptionAlgorithm]
  type PublicKey  = PublicKeyset[HybridEncryptionAlgorithm]

  def encrypt(plainText: Chunk[Byte], key: PublicKey): Task[CipherText[Chunk[Byte]]]
  def decrypt(ciphertext: CipherText[Chunk[Byte]], key: PrivateKey): Task[Chunk[Byte]]
  def encrypt(plainText: String, key: PublicKey, charset: Charset): Task[CipherText[String]]
  def decrypt(ciphertext: CipherText[String], key: PrivateKey, charset: Charset): Task[String]
}

private object HybridEncryptionLive extends HybridEncryption {
  override def encrypt(plainText: Chunk[Byte], key: PublicKey): Task[CipherText[Chunk[Byte]]] =
    Task.attempt(
      CipherText(Chunk.fromArray(key.handle.getPrimitive(classOf[HybridEncrypt]).encrypt(plainText.toArray, null)))
    )

  override def decrypt(ciphertext: CipherText[Chunk[Byte]], key: PrivateKey): Task[Chunk[Byte]] =
    Task.attempt(
      Chunk.fromArray(key.handle.getPrimitive(classOf[HybridDecrypt]).decrypt(ciphertext.value.toArray, null))
    )

  override def encrypt(plainText: String, key: PublicKey, charset: Charset): Task[CipherText[String]] =
    encrypt(Chunk.fromArray(plainText.getBytes(charset)), key)
      .map(x => CipherText(ByteHelpers.toB64String(x.value)))

  override def decrypt(ciphertext: CipherText[String], key: PrivateKey, charset: Charset): Task[String] =
    ByteHelpers
      .fromB64String(ciphertext.value) match {
      case Some(b) =>
        decrypt(CipherText(b), key)
          .map(x => new String(x.toArray, charset))
      case _       => Task.fail(new IllegalArgumentException("Ciphertext is not a base-64 encoded string"))
    }
}

object HybridEncryption {
  type PrivateKey = PrivateKeyset[HybridEncryptionAlgorithm]
  type PublicKey  = PublicKeyset[HybridEncryptionAlgorithm]

  val live: TaskLayer[HybridEncryption] = Task
    .attempt(HybridConfig.register())
    .as(HybridEncryptionLive)
    .toLayer

  /**
   * Encrypts the given `plainText`.
   *
   * @param plainText: The message to encrypt.
   * @param key: The public key to use to encrypt the message.
   * @return the `CipherText` generated from encrypting `plainText` with `key`.
   */
  def encrypt(plainText: Chunk[Byte], key: PublicKey): RIO[HybridEncryption, CipherText[Chunk[Byte]]] =
    ZIO.accessZIO(_.get.encrypt(plainText, key))

  /**
   * Encrypts the given `plainText`.
   *
   * @param plainText: The message to encrypt.
   * @param key: The public key to use to encrypt the message.
   * @param charset: The charset of `plainText`.
   * @return the `CipherText` generated from encrypting `plainText` with `key`.
   */
  def encrypt(plainText: String, key: PublicKey, charset: Charset): RIO[HybridEncryption, CipherText[String]] =
    ZIO.accessZIO(_.get.encrypt(plainText, key, charset))

  /**
   * Decrypts the given `ciphertext`.
   *
   * @param ciphertext: The ciphertext to decrypt.
   * @param key: The private key to use to decrypt the ciphertext
   * @return the plaintext decrypted from `ciphertext` under the `key`.
   */
  def decrypt(ciphertext: CipherText[Chunk[Byte]], key: PrivateKey): RIO[HybridEncryption, Chunk[Byte]] =
    ZIO.accessZIO(_.get.decrypt(ciphertext, key))

  /**
   * Decrypts the given `ciphertext`.
   *
   * @param ciphertext: The ciphertext to decrypt.
   * @param key: The private key to use to decrypt the ciphertext
   * @param charset: The charset of the original plaintext.
   * @return the plaintext decrypted from `ciphertext` under the `key`.
   */
  def decrypt(ciphertext: CipherText[String], key: PrivateKey, charset: Charset): RIO[HybridEncryption, String] =
    ZIO.accessZIO(_.get.decrypt(ciphertext, key, charset))

}
