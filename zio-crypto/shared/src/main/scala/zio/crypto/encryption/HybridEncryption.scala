package zio.crypto.encryption

import com.google.crypto.tink.hybrid.{EciesAeadHkdfPrivateKeyManager, HybridConfig}
import com.google.crypto.tink.{HybridDecrypt, HybridEncrypt, KeyTemplate => TinkKeyTemplate}
import zio._
import zio.crypto.ByteHelpers
import zio.crypto.keyset.{AsymmetricKeyset, KeyTemplate, PrivateKeyset, PublicKeyset}

import java.nio.charset.Charset

sealed trait HybridEncryptionAlgorithm

object HybridEncryptionAlgorithm {
  case object EciesP256HkdfHmacSha256Aes128Gcm           extends HybridEncryptionAlgorithm
  case object EciesP256HkdfHmacSha256Aes128CtrHmacSha256 extends HybridEncryptionAlgorithm

  implicit val template: KeyTemplate[HybridEncryptionAlgorithm] with AsymmetricKeyset[HybridEncryptionAlgorithm] =
    new KeyTemplate[HybridEncryptionAlgorithm] with AsymmetricKeyset[HybridEncryptionAlgorithm] {
      override def getTinkKeyTemplate(a: HybridEncryptionAlgorithm): TinkKeyTemplate =
        a match {
          case HybridEncryptionAlgorithm.EciesP256HkdfHmacSha256Aes128CtrHmacSha256 =>
            EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128CtrHmacSha256Template()
          case HybridEncryptionAlgorithm.EciesP256HkdfHmacSha256Aes128Gcm =>
            EciesAeadHkdfPrivateKeyManager.eciesP256HkdfHmacSha256Aes128GcmTemplate()
        }
    }
}

object HybridEncryption {
  type HybridEncryption = Has[HybridEncryption.Service]
  type PrivateKey       = PrivateKeyset[HybridEncryptionAlgorithm]
  type PublicKey        = PublicKeyset[HybridEncryptionAlgorithm]

  trait Service {
    def encrypt(plainText: Chunk[Byte], key: PublicKey): Task[CipherText[Chunk[Byte]]]
    def decrypt(ciphertext: CipherText[Chunk[Byte]], key: PrivateKey): Task[Chunk[Byte]]
    def encrypt(plainText: String, key: PublicKey, charset: Charset): Task[CipherText[String]]
    def decrypt(ciphertext: CipherText[String], key: PrivateKey, charset: Charset): Task[String]
  }

  val live: TaskLayer[HybridEncryption] = Task
    .effect(HybridConfig.register())
    .as(new Service {
      override def encrypt(plainText: Chunk[Byte], key: PublicKey): Task[CipherText[Chunk[Byte]]] =
        Task.effect(
          CipherText(Chunk.fromArray(key.handle.getPrimitive(classOf[HybridEncrypt]).encrypt(plainText.toArray, null)))
        )

      override def decrypt(ciphertext: CipherText[Chunk[Byte]], key: PrivateKey): Task[Chunk[Byte]] =
        Task.effect(
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
          case _ => Task.fail(new IllegalArgumentException("Ciphertext is not a base-64 encoded string"))
        }

    })
    .toLayer

  /**
   * Encrypts the given `plainText`.
   *
   * @param plainText: The message to encrypt.
   * @param key: The public key to use to encrypt the message.
   * @return the `CipherText` generated from encrypting `plainText` with `key`.
   */
  def encrypt(plainText: Chunk[Byte], key: PublicKey): RIO[HybridEncryption, CipherText[Chunk[Byte]]] =
    ZIO.accessM(_.get.encrypt(plainText, key))

  /**
   * Encrypts the given `plainText`.
   *
   * @param plainText: The message to encrypt.
   * @param key: The public key to use to encrypt the message.
   * @param charset: The charset of `plainText`.
   * @return the `CipherText` generated from encrypting `plainText` with `key`.
   */
  def encrypt(plainText: String, key: PublicKey, charset: Charset): RIO[HybridEncryption, CipherText[String]] =
    ZIO.accessM(_.get.encrypt(plainText, key, charset))

  /**
   * Decrypts the given `ciphertext`.
   *
   * @param ciphertext: The ciphertext to decrypt.
   * @param key: The private key to use to decrypt the ciphertext
   * @return the plaintext decrypted from `ciphertext` under the `key`.
   */
  def decrypt(ciphertext: CipherText[Chunk[Byte]], key: PrivateKey): RIO[HybridEncryption, Chunk[Byte]] =
    ZIO.accessM(_.get.decrypt(ciphertext, key))

  /**
   * Decrypts the given `ciphertext`.
   *
   * @param ciphertext: The ciphertext to decrypt.
   * @param key: The private key to use to decrypt the ciphertext
   * @param charset: The charset of the original plaintext.
   * @return the plaintext decrypted from `ciphertext` under the `key`.
   */
  def decrypt(ciphertext: CipherText[String], key: PrivateKey, charset: Charset): RIO[HybridEncryption, String] =
    ZIO.accessM(_.get.decrypt(ciphertext, key, charset))

}
