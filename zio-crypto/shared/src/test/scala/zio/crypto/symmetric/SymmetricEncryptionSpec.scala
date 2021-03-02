package zio.crypto.symmetric

import java.nio.charset.StandardCharsets.US_ASCII

import zio.crypto.random.SecureRandom
import zio.test.Assertion._
import zio.test._

object SymmetricEncryptionSpec extends DefaultRunnableSpec {

  private def testAlgorithm(algorithm: SymmetricEncryptionAlgorithm) = suite(algorithm.toString)(
    suite("bytes")(
      testM("encrypt(m, k) != encrypt(m, k)") {
        checkM(Gen.chunkOf(Gen.anyByte)) { m =>
          for {
            key         <- SymmetricEncryption.getKey(algorithm)
            ciphertext1 <- SymmetricEncryption.encrypt(m, key)
            ciphertext2 <- SymmetricEncryption.encrypt(m, key)
          } yield assert(ciphertext1)(not(equalTo(ciphertext2)))
        }
      },
      testM("decrypt(encrypt(m, k), k) == m") {
        checkM(Gen.chunkOf(Gen.anyByte)) { m =>
          for {
            key        <- SymmetricEncryption.getKey(algorithm)
            ciphertext <- SymmetricEncryption.encrypt(m, key)
            decrypted  <- SymmetricEncryption.decrypt(ciphertext, key)
          } yield assert(decrypted)(equalTo(m))
        }
      }
    ),
    suite("string")(
      testM("encrypt(m, k) != encrypt(m, k)") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            key         <- SymmetricEncryption.getKey(algorithm)
            ciphertext1 <- SymmetricEncryption.encrypt(m, key, US_ASCII)
            ciphertext2 <- SymmetricEncryption.encrypt(m, key, US_ASCII)
          } yield assert(ciphertext1)(not(equalTo(ciphertext2)))
        }
      },
      testM("decrypt(encrypt(m, k), k) == m") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            key        <- SymmetricEncryption.getKey(algorithm)
            ciphertext <- SymmetricEncryption.encrypt(m, key, US_ASCII)
            decrypted  <- SymmetricEncryption.decrypt(ciphertext, key, US_ASCII)
          } yield assert(decrypted)(equalTo(m))
        }
      }
    )
  )

  def spec: Spec[Environment, TestFailure[Throwable], TestSuccess] = suite("SymmetricEncryptionSpec")(
    testAlgorithm(SymmetricEncryptionAlgorithm.AES128),
    testAlgorithm(SymmetricEncryptionAlgorithm.AES192),
    testAlgorithm(SymmetricEncryptionAlgorithm.AES256)
  ).provideCustomLayer(SecureRandom.live.orDie ++ SymmetricEncryption.live)
}
