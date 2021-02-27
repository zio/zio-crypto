package zio.crypto.symmetric

import zio._
import zio.crypto.random.SecureRandom
import zio.crypto.random.SecureRandom.SecureRandom

import javax.crypto.spec.GCMParameterSpec
import javax.crypto.{ Cipher, KeyGenerator, SecretKey }

sealed trait SymmetricEncryptionAlgorithm

object SymmetricEncryptionAlgorithm {
  case object AES128 extends SymmetricEncryptionAlgorithm
  case object AES192 extends SymmetricEncryptionAlgorithm
  case object AES256 extends SymmetricEncryptionAlgorithm
}

case class CipherText(value: Array[Byte])           extends AnyVal
case class SymmetricEncryptionKey(value: SecretKey) extends AnyVal

object SymmetricEncryption {

  type SymmetricEncryption = Has[SymmetricEncryption.Service]

  trait Service {
    def encrypt(plainText: Array[Byte], key: SymmetricEncryptionKey): RIO[SecureRandom, CipherText]
    def decrypt(ciphertext: CipherText, key: SymmetricEncryptionKey): Task[Array[Byte]]
    def getKey(alg: SymmetricEncryptionAlgorithm): RIO[SecureRandom, SymmetricEncryptionKey]
  }

  val live: ULayer[SymmetricEncryption] = ZLayer.succeed(new Service {

    /**
     * In our implementation, we will use the most secure tag size as defined
     * by: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
     * Iv length of 96 bits is recommended as per the spec on page 8
     */
    val NISTTagLengthBits = 128
    val NISTIvLengthBytes = 12

    private def getInstance: Task[Cipher] =
      Task.effect(Cipher.getInstance("AES/GCM/NoPadding"))

    override def encrypt(plainText: Array[Byte], key: SymmetricEncryptionKey): RIO[SecureRandom, CipherText] =
      for {
        iv       <- SecureRandom.nextBytes(NISTIvLengthBytes)
        instance <- getInstance
        ciphertext <- Task.effect {
                        instance.init(
                          Cipher.ENCRYPT_MODE,
                          key.value,
                          new GCMParameterSpec(NISTTagLengthBits, iv.toArray)
                        )
                        instance.doFinal(plainText.toArray)
                      }
      } yield CipherText(iv ++ ciphertext)

    override def decrypt(ciphertext: CipherText, key: SymmetricEncryptionKey): Task[Array[Byte]] = for {
      instance <- getInstance
      message <- Task.effect {
                   val (iv, encrypted) = ciphertext.value.splitAt(NISTIvLengthBytes)
                   instance.init(
                     Cipher.DECRYPT_MODE,
                     key.value,
                     new GCMParameterSpec(NISTTagLengthBits, iv.toArray)
                   )
                   instance.doFinal(encrypted.toArray)
                 }
    } yield message

    override def getKey(alg: SymmetricEncryptionAlgorithm): RIO[SecureRandom, SymmetricEncryptionKey] =
      for {
        random <- SecureRandom.getJavaSecureRandom
        key <- Task.effect {
                 val keyGen = KeyGenerator.getInstance("AES")
                 val keysize = alg match {
                   case SymmetricEncryptionAlgorithm.AES128 => 128
                   case SymmetricEncryptionAlgorithm.AES192 => 192
                   case SymmetricEncryptionAlgorithm.AES256 => 256
                 }
                 keyGen.init(keysize, random)
                 keyGen.generateKey
               }
      } yield SymmetricEncryptionKey(key)

  })

  /**
   * Encrypts the given `plainText`.
   *
   * @param plainText: The message to encrypt.
   * @param key: The key to use to encrypt the message.
   * @return the ciphertext generated from encrypting `plainText` with `key`.
   */
  def encrypt(
    plainText: Array[Byte],
    key: SymmetricEncryptionKey
  ): RIO[SymmetricEncryption with SecureRandom, CipherText] =
    ZIO.accessM(_.get.encrypt(plainText, key))

  /**
   * Decrypts the given `ciphertext`.
   *
   * @param ciphertext: The ciphertext to decrypt.
   * @param key: The key to use to decrypt the ciphertext
   * @return the plaintext decrypted from the `CipherText` `ciphertext` under the `SymmetricEncryptionKey` `key`.
   */
  def decrypt(ciphertext: CipherText, key: SymmetricEncryptionKey): RIO[SymmetricEncryption, Array[Byte]] =
    ZIO.accessM(_.get.decrypt(ciphertext, key))

  /**
   * Generates a symmetric encryption key for the given algorithm `alg`.
   *
   * @param alg: The `SymmetricEncryptionAlgorithm` for which to generate a key.
   * @return the symmetric encryption key.
   */
  def getKey(alg: SymmetricEncryptionAlgorithm): RIO[SymmetricEncryption with SecureRandom, SymmetricEncryptionKey] =
    ZIO.accessM(_.get.getKey(alg))

}
