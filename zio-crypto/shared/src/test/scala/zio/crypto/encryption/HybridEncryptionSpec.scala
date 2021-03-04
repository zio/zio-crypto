package zio.crypto.encryption

import zio.crypto.keyset.KeysetManager
import zio.test.Assertion._
import zio.test._

import java.nio.charset.StandardCharsets.US_ASCII

object HybridEncryptionSpec extends DefaultRunnableSpec {

  private def testAlgorithm(algorithm: HybridEncryptionAlgorithm) = suite(algorithm.toString)(
    suite("bytes")(
      testM("encrypt(m, k) != encrypt(m, k)") {
        checkM(Gen.chunkOf(Gen.anyByte)) { m =>
          for {
            key         <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext1 <- HybridEncryption.encrypt(m, key.publicKeyset)
            ciphertext2 <- HybridEncryption.encrypt(m, key.publicKeyset)
          } yield assert(ciphertext1)(not(equalTo(ciphertext2)))
        }
      },
      testM("decrypt(encrypt(m, k), k) == m") {
        checkM(Gen.chunkOf(Gen.anyByte)) { m =>
          for {
            key        <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext <- HybridEncryption.encrypt(m, key.publicKeyset)
            decrypted  <- HybridEncryption.decrypt(ciphertext, key)
          } yield assert(decrypted)(equalTo(m))
        }
      }
    ),
    suite("string")(
      testM("encrypt(m, k) != encrypt(m, k)") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            key         <- KeysetManager.generateNewAsymmetric(algorithm)
            ciphertext1 <- HybridEncryption.encrypt(m, key.publicKeyset, US_ASCII)
            ciphertext2 <- HybridEncryption.encrypt(m, key.publicKeyset, US_ASCII)
          } yield assert(ciphertext1)(not(equalTo(ciphertext2)))
        }
      },
      testM("decrypt(encrypt(m, k), k) == m") {
        checkM(Gen.anyASCIIString) { m =>
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
