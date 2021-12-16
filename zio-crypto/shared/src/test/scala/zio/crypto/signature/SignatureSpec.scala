package zio.crypto.signature

import java.nio.charset.StandardCharsets.US_ASCII

import zio.crypto.keyset.KeysetManager
import zio.test.Assertion._
import zio.test._
import zio.test.{ Gen, ZIOSpecDefault }

object SignatureSpec extends ZIOSpecDefault {
  private def testAlgorithm(alg: SignatureAlgorithm) = suite(alg.toString)(
    suite("bytes")(
      test("verify(m, sign(m)) = true") {
        check(Gen.chunkOf(Gen.byte)) { m =>
          for {
            k         <- KeysetManager.generateNewAsymmetric(alg)
            signature <- Signature.sign(m, k)
            verified  <- Signature.verify(m, signature, k.publicKeyset)
          } yield assert(verified)(isTrue)
        }
      },
      test("verify(m1, sign(m0)) = false") {
        check(Gen.chunkOf(Gen.byte), Gen.chunkOf(Gen.byte)) {
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
      test("verify(m, sign(m)) = true") {
        check(Gen.asciiString) { m =>
          for {
            k         <- KeysetManager.generateNewAsymmetric(alg)
            signature <- Signature.sign(m, k, US_ASCII)
            verified  <- Signature.verify(m, signature, k.publicKeyset, US_ASCII)
          } yield assert(verified)(isTrue)
        }
      },
      test("verify(m1, sign(m0)) = false") {
        check(Gen.asciiString, Gen.asciiString) {
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
    testAlgorithm(SignatureAlgorithm.ED25519),
    testAlgorithm(SignatureAlgorithm.Rsa3072SsaPkcs1Sha256F4)
  ).provideCustomLayer(Signature.live.orDie ++ KeysetManager.live)
}
