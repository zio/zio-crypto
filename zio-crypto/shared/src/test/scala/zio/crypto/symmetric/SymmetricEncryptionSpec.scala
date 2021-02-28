package zio.crypto.symmetric

import zio.crypto.random.SecureRandom
import zio.test.Assertion._
import zio.test._

object SymmetricEncryptionSpec extends DefaultRunnableSpec {

  private def testAlgorithm(algorithm: SymmetricEncryptionAlgorithm) = suite(algorithm.toString)(
    suite("bytes")(
      testM("decrypt(encrypt(m, k), k) == m") {
        checkM(Gen.chunkOf(Gen.anyByte)) { m =>
          for {
            key        <- SymmetricEncryption.getKey(algorithm)
            ciphertext <- SymmetricEncryption.encrypt(m, key)
            decrypted  <- SymmetricEncryption.decrypt(ciphertext, key)
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
