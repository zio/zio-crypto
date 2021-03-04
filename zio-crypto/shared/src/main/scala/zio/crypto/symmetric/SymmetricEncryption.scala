package zio.crypto.symmetric

import com.google.crypto.tink.aead.{AeadConfig, AesGcmKeyManager}
import com.google.crypto.tink.{Aead, KeyTemplate => TinkKeyTemplate}
import zio._
import zio.crypto.ByteHelpers
import zio.crypto.keyset.{KeyTemplate, Keyset, SymmetricKeyset}

import java.nio.charset.Charset

sealed trait SymmetricEncryptionAlgorithm

object SymmetricEncryptionAlgorithm {
  case object AES128GCM extends SymmetricEncryptionAlgorithm
  case object AES256GCM extends SymmetricEncryptionAlgorithm

  implicit val template: KeyTemplate[SymmetricEncryptionAlgorithm] with SymmetricKeyset[SymmetricEncryptionAlgorithm] =
    new KeyTemplate[SymmetricEncryptionAlgorithm] with SymmetricKeyset[SymmetricEncryptionAlgorithm] {
      override def getTinkKeyTemplate(a: SymmetricEncryptionAlgorithm): TinkKeyTemplate =
        a match {
          case SymmetricEncryptionAlgorithm.AES128GCM => AesGcmKeyManager.aes128GcmTemplate()
          case SymmetricEncryptionAlgorithm.AES256GCM => AesGcmKeyManager.aes256GcmTemplate()
        }
    }
}

case class CipherText[T](value: T) extends AnyVal

object SymmetricEncryption {
  type SymmetricEncryption = Has[SymmetricEncryption.Service]
  type KEY                 = Keyset[SymmetricEncryptionAlgorithm]

  trait Service {
    def encrypt(plainText: Chunk[Byte], key: KEY): Task[CipherText[Chunk[Byte]]]
    def decrypt(ciphertext: CipherText[Chunk[Byte]], key: KEY): Task[Chunk[Byte]]
    def encrypt(plainText: String, key: KEY, charset: Charset): Task[CipherText[String]]
    def decrypt(ciphertext: CipherText[String], key: KEY, charset: Charset): Task[String]
  }

  val live: TaskLayer[SymmetricEncryption] = Task
    .effect(AeadConfig.register())
    .as(new Service {
      override def encrypt(plainText: Chunk[Byte], key: KEY): Task[CipherText[Chunk[Byte]]] =
        Task.effect(
          CipherText(Chunk.fromArray(key.handle.getPrimitive(classOf[Aead]).encrypt(plainText.toArray, null)))
        )

      override def decrypt(ciphertext: CipherText[Chunk[Byte]], key: KEY): Task[Chunk[Byte]] =
        Task.effect(
          Chunk.fromArray(key.handle.getPrimitive(classOf[Aead]).decrypt(ciphertext.value.toArray, null))
        )

      override def encrypt(plainText: String, key: KEY, charset: Charset): Task[CipherText[String]] =
        encrypt(Chunk.fromArray(plainText.getBytes(charset)), key)
          .map(x => CipherText(ByteHelpers.toB64String(x.value)))

      override def decrypt(ciphertext: CipherText[String], key: KEY, charset: Charset): Task[String] =
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
   * @param key: The key to use to encrypt the message.
   * @return the ciphertext generated from encrypting `plainText` with `key`.
   */
  def encrypt(plainText: Chunk[Byte], key: KEY): RIO[SymmetricEncryption, CipherText[Chunk[Byte]]] =
    ZIO.accessM(_.get.encrypt(plainText, key))

  /**
   * Encrypts the given `plainText`.
   *
   * @param plainText: The message to encrypt.
   * @param key: The key to use to encrypt the message.
   * @param charset: The charset of `plainText`.
   * @return the ciphertext generated from encrypting `plainText` with `key`.
   */
  def encrypt(plainText: String, key: KEY, charset: Charset): RIO[SymmetricEncryption, CipherText[String]] =
    ZIO.accessM(_.get.encrypt(plainText, key, charset))

  /**
   * Decrypts the given `ciphertext`.
   *
   * @param ciphertext: The ciphertext to decrypt.
   * @param key: The key to use to decrypt the ciphertext
   * @return the plaintext decrypted from the `CipherText` `ciphertext` under the `SymmetricEncryptionKey` `key`.
   */
  def decrypt(ciphertext: CipherText[Chunk[Byte]], key: KEY): RIO[SymmetricEncryption, Chunk[Byte]] =
    ZIO.accessM(_.get.decrypt(ciphertext, key))

  /**
   * Decrypts the given `ciphertext`.
   *
   * @param ciphertext: The ciphertext to decrypt.
   * @param key: The key to use to decrypt the ciphertext
   * @param charset: The charset of the original plaintext.
   * @return the plaintext decrypted from the `CipherText` `ciphertext` under the `SymmetricEncryptionKey` `key`.
   */
  def decrypt(ciphertext: CipherText[String], key: KEY, charset: Charset): RIO[SymmetricEncryption, String] =
    ZIO.accessM(_.get.decrypt(ciphertext, key, charset))

}
