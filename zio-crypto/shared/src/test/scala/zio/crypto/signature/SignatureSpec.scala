package zio.crypto.signature

import java.nio.charset.StandardCharsets.US_ASCII

import zio._
import zio.crypto.keyset.KeysetManager
import zio.test.Assertion._
import zio.test._

object SignatureSpec extends DefaultRunnableSpec {
  private val assertCompletesM = assertM(UIO(true))(isTrue)

  private def testAlgorithm(alg: SignatureAlgorithm) = suite(alg.toString)(
    suite("bytes")(
      testM("verify(m, sign(m)) = true") {
        checkM(Gen.chunkOf(Gen.anyByte)) { m =>
          for {
            k         <- KeysetManager.generateNewAsymmetric(alg)
            signature <- Signature.sign(m, k)
            verified  <- Signature.verify(m, signature, k.publicKeyset)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m1, sign(m0)) = false") {
        checkM(Gen.chunkOf(Gen.anyByte), Gen.chunkOf(Gen.anyByte)) {
          case (m0, m1) if m0 != m1 =>
            for {
              k         <- KeysetManager.generateNewAsymmetric(alg)
              signature <- Signature.sign(m0, k)
              verified  <- Signature.verify(m1, signature, k.publicKeyset)
            } yield assert(verified)(isFalse)
          case _                    => assertCompletesM
        }
      }
    ),
    suite("string")(
      testM("verify(m, sign(m)) = true") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            k         <- KeysetManager.generateNewAsymmetric(alg)
            signature <- Signature.sign(m, k, US_ASCII)
            verified  <- Signature.verify(m, signature, k.publicKeyset, US_ASCII)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m1, sign(m0)) = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) {
          case (m0, m1) if m0 != m1 =>
            for {
              k         <- KeysetManager.generateNewAsymmetric(alg)
              signature <- Signature.sign(m0, k, US_ASCII)
              verified  <- Signature.verify(m1, signature, k.publicKeyset, US_ASCII)
            } yield assert(verified)(isFalse)
          case _                    => assertCompletesM
        }
      }
    )
  )

  def spec: Spec[Environment, TestFailure[Throwable], TestSuccess] = suite("SignatureSpec")(
    testAlgorithm(SignatureAlgorithm.ECDSA_P256),
    testAlgorithm(SignatureAlgorithm.ED25519)
  ).provideCustomLayer(Signature.live.orDie ++ KeysetManager.live)
}
