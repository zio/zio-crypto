package zio.crypto.signature

import zio._
import zio.crypto.random.SecureRandom
import zio.test.Assertion.{ isFalse, isTrue }
import zio.test._

object SignatureSpec extends DefaultRunnableSpec {
  private val assertCompletesM = assertM(UIO(true))(isTrue)

  private def testAlgorithm(alg: SignatureAlgorithm) = suite(alg.toString)(
    suite("bytes")(
      testM("verify(m, sign(m)) = true") {
        checkM(Gen.chunkOf(Gen.anyByte)) { m =>
          for {
            k         <- Signature.genKey(alg)
            signature <- Signature.sign(m, k.privateKey)
            verified  <- Signature.verify(m, signature, k.publicKey)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m1, sign(m0)) = false") {
        checkM(Gen.chunkOf(Gen.anyByte), Gen.chunkOf(Gen.anyByte)) {
          case (m0, m1) if m0 != m1 =>
            for {
              k         <- Signature.genKey(alg)
              signature <- Signature.sign(m0, k.privateKey)
              verified  <- Signature.verify(m1, signature, k.publicKey)
            } yield assert(verified)(isFalse)
          case _ => assertCompletesM
        }
      }
    )
  )

  def spec: Spec[Environment, TestFailure[Throwable], TestSuccess] = suite("SignatureSpec")(
    testAlgorithm(SignatureAlgorithm.ECDSASHA256),
    testAlgorithm(SignatureAlgorithm.ECDSASHA384),
    testAlgorithm(SignatureAlgorithm.ECDSASHA512)
  ).provideCustomLayer(Signature.live ++ SecureRandom.live.orDie)
}
