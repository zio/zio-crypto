package zio.crypto.encryption

import java.nio.charset.StandardCharsets.US_ASCII

import zio.crypto.keyset.KeysetManager
import zio.test.Assertion._
import zio.test._
import zio.test.{ Gen, ZIOSpecDefault }

object HybridEncryptionSpec extends ZIOSpecDefault {

  private def testAlgorithm(algorithm: HybridEncryptionAlgorithm) = suite(algorithm.toString)(
    suite("bytes")(
      test("encrypt(m, k) != encrypt(m, k)") {
        check(Gen.chunkOf(Gen.byte)) { m =>
          for {
            key         <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext1 <- HybridEncryption.encrypt(m, key.publicKeyset)
            ciphertext2 <- HybridEncryption.encrypt(m, key.publicKeyset)
          } yield assert(ciphertext1)(not(equalTo(ciphertext2)))
        }
      },
      test("decrypt(encrypt(m, k), k) == m") {
        check(Gen.chunkOf(Gen.byte)) { m =>
          for {
            key        <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext <- HybridEncryption.encrypt(m, key.publicKeyset)
            decrypted  <- HybridEncryption.decrypt(ciphertext, key)
          } yield assert(decrypted)(equalTo(m))
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
          } yield assert(ciphertext1)(not(equalTo(ciphertext2)))
        }
      },
      test("decrypt(encrypt(m, k), k) == m") {
        check(Gen.asciiString) { m =>
          for {
            key        <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext <- HybridEncryption.encrypt(m, key.publicKeyset, US_ASCII)
            decrypted  <- HybridEncryption.decrypt(ciphertext, key, US_ASCII)
          } yield assert(decrypted)(equalTo(m))
        }
      }
    )
  )

  def spec: Spec[Environment, TestFailure[Throwable], TestSuccess] = suite("HybridEncryptionSpec")(
    testAlgorithm(HybridEncryptionAlgorithm.EciesP256HkdfHmacSha256Aes128CtrHmacSha256),
    testAlgorithm(HybridEncryptionAlgorithm.EciesP256HkdfHmacSha256Aes128Gcm)
  ).provideCustomLayer(KeysetManager.live ++ HybridEncryption.live.orDie)
}
