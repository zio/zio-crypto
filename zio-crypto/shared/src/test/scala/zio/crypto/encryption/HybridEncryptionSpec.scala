package zio.crypto.encryption

import zio.Scope
import zio.crypto.keyset.KeysetManager
import zio.test._

import java.nio.charset.StandardCharsets.US_ASCII

object HybridEncryptionSpec extends ZIOSpecDefault {

  private def testAlgorithm(algorithm: HybridEncryptionAlgorithm) = suite(algorithm.toString)(
    suite("bytes")(
      test("encrypt(m, k) != encrypt(m, k)") {
        check(Gen.chunkOf(Gen.byte)) { m =>
          for {
            key         <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext1 <- HybridEncryption.encrypt(m, key.publicKeyset)
            ciphertext2 <- HybridEncryption.encrypt(m, key.publicKeyset)
          } yield assertTrue(!(ciphertext1 == ciphertext2))
        }
      },
      test("decrypt(encrypt(m, k), k) == m") {
        check(Gen.chunkOf(Gen.byte)) { m =>
          for {
            key        <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext <- HybridEncryption.encrypt(m, key.publicKeyset)
            decrypted  <- HybridEncryption.decrypt(ciphertext, key)
          } yield assertTrue(decrypted == m)
        }
      }
    ),
    suite("string")(
      test("encrypt(m, k) != encrypt(m, k)") {
        check(Gen.asciiString) { m =>
          for {
            key         <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext1 <- HybridEncryption.encrypt(m, key.publicKeyset, US_ASCII)
            ciphertext2 <- HybridEncryption.encrypt(m, key.publicKeyset, US_ASCII)
          } yield assertTrue(!(ciphertext1 == ciphertext2))
        }
      },
      test("decrypt(encrypt(m, k), k) == m") {
        check(Gen.asciiString) { m =>
          for {
            key        <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext <- HybridEncryption.encrypt(m, key.publicKeyset, US_ASCII)
            decrypted  <- HybridEncryption.decrypt(ciphertext, key, US_ASCII)
          } yield assertTrue(decrypted == m)
        }
      }
    )
  )

  def spec: Spec[TestEnvironment with Scope, Any] = suite("HybridEncryptionSpec")(
    testAlgorithm(HybridEncryptionAlgorithm.EciesP256HkdfHmacSha256Aes128CtrHmacSha256),
    testAlgorithm(HybridEncryptionAlgorithm.EciesP256HkdfHmacSha256Aes128Gcm)
  ).provideCustomLayer(KeysetManager.live ++ HybridEncryption.live.orDie)
}
