package zio.crypto.symmetric

import zio.crypto.random.SecureRandom
import zio.test.Assertion._
import zio.test._

object SymmetricEncryptionSpec extends DefaultRunnableSpec {

  private def testAlgorithm(algorithm: SymmetricEncryptionAlgorithm) = suite(algorithm.toString)(
    suite("bytes")(
      testM("decrypt(encrypt(m)) == m") {
        checkM(Gen.listOf(Gen.anyByte)) { m =>
          for {
            key        <- SymmetricEncryption.getAESKey(algorithm)
            ciphertext <- SymmetricEncryption.encrypt(m, key)
            decrypted  <- SymmetricEncryption.decrypt(ciphertext, key)
          } yield assert(decrypted)(equalTo(m))
        }
      }
    )
  )

  def spec: Spec[Environment, TestFailure[Throwable], TestSuccess] = suite("HashingSpec")(
    testAlgorithm(SymmetricEncryptionAlgorithm.AES128),
    testAlgorithm(SymmetricEncryptionAlgorithm.AES192),
    testAlgorithm(SymmetricEncryptionAlgorithm.AES256)
  ).provideSomeLayer[Environment](SecureRandom.live.orDie ++ SymmetricEncryption.live)
}
