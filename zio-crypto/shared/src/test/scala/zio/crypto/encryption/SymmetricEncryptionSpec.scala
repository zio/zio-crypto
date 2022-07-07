package zio.crypto.encryption

import java.nio.charset.StandardCharsets.US_ASCII

import zio.Scope
import zio.crypto.keyset.KeysetManager
import zio.test._

object SymmetricEncryptionSpec extends ZIOSpecDefault {

  private def testAlgorithm(algorithm: SymmetricEncryptionAlgorithm) = suite(algorithm.toString)(
    suite("bytes")(
      test("encrypt(m, k) != encrypt(m, k)") {
        check(Gen.chunkOf(Gen.byte)) { m =>
          for {
            key         <- KeysetManager.generateNewSymmetric(algorithm)
            ciphertext1 <- SymmetricEncryption.encrypt(m, key)
            ciphertext2 <- SymmetricEncryption.encrypt(m, key)
          } yield assertTrue(!(ciphertext1 == ciphertext2))
        }
      },
      test("decrypt(encrypt(m, k), k) == m") {
        check(Gen.chunkOf(Gen.byte)) { m =>
          for {
            key        <- KeysetManager.generateNewSymmetric(algorithm)
            ciphertext <- SymmetricEncryption.encrypt(m, key)
            decrypted  <- SymmetricEncryption.decrypt(ciphertext, key)
          } yield assertTrue(decrypted == m)
        }
      }
    ),
    suite("string")(
      test("encrypt(m, k) != encrypt(m, k)") {
        check(Gen.asciiString) { m =>
          for {
            key         <- KeysetManager.generateNewSymmetric(algorithm)
            ciphertext1 <- SymmetricEncryption.encrypt(m, key, US_ASCII)
            ciphertext2 <- SymmetricEncryption.encrypt(m, key, US_ASCII)
          } yield assertTrue(!(ciphertext1 == ciphertext2))
        }
      },
      test("decrypt(encrypt(m, k), k) == m") {
        check(Gen.asciiString) { m =>
          for {
            key        <- KeysetManager.generateNewSymmetric(algorithm)
            ciphertext <- SymmetricEncryption.encrypt(m, key, US_ASCII)
            decrypted  <- SymmetricEncryption.decrypt(ciphertext, key, US_ASCII)
          } yield assertTrue(decrypted == m)
        }
      }
    )
  )

  def spec: Spec[TestEnvironment with Scope, Any] = suite("SymmetricEncryptionSpec")(
    testAlgorithm(SymmetricEncryptionAlgorithm.AES128GCM),
    testAlgorithm(SymmetricEncryptionAlgorithm.AES256GCM)
  ).provideCustomLayer(KeysetManager.live ++ SymmetricEncryption.live.orDie)
}
