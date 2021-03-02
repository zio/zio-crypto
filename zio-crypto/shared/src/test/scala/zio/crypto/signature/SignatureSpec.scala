package zio.crypto.signature

import java.nio.charset.StandardCharsets.US_ASCII

import zio._
import zio.crypto.random.SecureRandom
import zio.test.Assertion._
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
          case _                    => assertCompletesM
        }
      },
      testM("sign(m, k) != sign(m, k)") {
        checkM(Gen.chunkOf(Gen.anyByte)) { m =>
          for {
            k          <- Signature.genKey(alg)
            signature1 <- Signature.sign(m, k.privateKey)
            signature2 <- Signature.sign(m, k.privateKey)
          } yield assert(signature1)(not(equalTo(signature2)))
        }
      }
    ),
    suite("string")(
      testM("verify(m, sign(m)) = true") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            k         <- Signature.genKey(alg)
            signature <- Signature.sign(m, k.privateKey, US_ASCII)
            verified  <- Signature.verify(m, signature, k.publicKey, US_ASCII)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m1, sign(m0)) = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) {
          case (m0, m1) if m0 != m1 =>
            for {
              k         <- Signature.genKey(alg)
              signature <- Signature.sign(m0, k.privateKey, US_ASCII)
              verified  <- Signature.verify(m1, signature, k.publicKey, US_ASCII)
            } yield assert(verified)(isFalse)
          case _                    => assertCompletesM
        }
      },
      testM("sign(m, k) != sign(m, k)") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            k          <- Signature.genKey(alg)
            signature1 <- Signature.sign(m, k.privateKey, US_ASCII)
            signature2 <- Signature.sign(m, k.privateKey, US_ASCII)
          } yield assert(signature1)(not(equalTo(signature2)))
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
