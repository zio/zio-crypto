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

object SymmetricEncryption {

  type SymmetricEncryption = Has[SymmetricEncryption.Service]

  trait Service {
    def encrypt(plainText: Seq[Byte], key: SecretKey): RIO[SecureRandom, Seq[Byte]]
    def decrypt(ciphertext: Seq[Byte], key: SecretKey): Task[Seq[Byte]]
    def getAESKey(alg: SymmetricEncryptionAlgorithm): RIO[SecureRandom, SecretKey]
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

    override def encrypt(plainText: Seq[Byte], key: SecretKey): RIO[SecureRandom, Seq[Byte]] =
      for {
        iv       <- SecureRandom.nextBytes(NISTIvLengthBytes)
        instance <- getInstance
        ciphertext <- Task.effect {
                        instance.init(
                          Cipher.ENCRYPT_MODE,
                          key,
                          new GCMParameterSpec(NISTTagLengthBits, iv.toArray)
                        )
                        instance.doFinal(plainText.toArray)
                      }
      } yield iv ++ ciphertext

    override def decrypt(ciphertext: Seq[Byte], key: SecretKey): Task[Seq[Byte]] = for {
      instance <- getInstance
      message <- Task.effect {
                   val (iv, encrypted) = ciphertext.splitAt(NISTIvLengthBytes)
                   instance.init(
                     Cipher.DECRYPT_MODE,
                     key,
                     new GCMParameterSpec(NISTTagLengthBits, iv.toArray)
                   )
                   instance.doFinal(encrypted.toArray)
                 }
    } yield message

    override def getAESKey(alg: SymmetricEncryptionAlgorithm): RIO[SecureRandom, SecretKey] =
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
      } yield key

  })

  def encrypt(plainText: Seq[Byte], key: SecretKey): RIO[SymmetricEncryption with SecureRandom, Seq[Byte]] =
    ZIO.accessM(_.get.encrypt(plainText, key))

  def decrypt(ciphertext: Seq[Byte], key: SecretKey): RIO[SymmetricEncryption, Seq[Byte]] =
    ZIO.accessM(_.get.decrypt(ciphertext, key))

  def getAESKey(alg: SymmetricEncryptionAlgorithm): RIO[SymmetricEncryption with SecureRandom, SecretKey] =
    ZIO.accessM(_.get.getAESKey(alg))

}
