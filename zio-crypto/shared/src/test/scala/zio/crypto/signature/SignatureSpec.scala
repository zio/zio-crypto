package zio.crypto.signature

import zio._
import zio.crypto.random.SecureRandom
import zio.test.Assertion.{ isFalse, isTrue }
import zio.test._

object SignatureSpec extends DefaultRunnableSpec {
  private val assertCompletesM = assertM(UIO(true))(isTrue)

  private def testAlgorithm(alg: SignatureAlgorithm) = suite(alg.toString)(
//    suite("keys")(
//      testM("deserialize(serialize(k)) = k") {
//        for {
//          k             <- HMAC.genKey(alg)
//          serializedK   <- HMAC.serializeKey(k)
//          deserializedK <- HMAC.deserializeKey(serializedK)
//        } yield assert(k)(equalTo(deserializedK))
//      },
//      testM("work through serialization") {
//        checkM(Gen.anyASCIIString) { m =>
//          for {
//            k             <- HMAC.genKey(alg)
//            serializedK   <- HMAC.serializeKey(k)
//            deserializedK <- HMAC.deserializeKey(serializedK)
//
//            hmac     <- HMAC.sign(m, k, alg, US_ASCII)
//            verified <- HMAC.verify(m, hmac, deserializedK, alg, US_ASCII)
//          } yield assert(verified)(isTrue)
//        }
//      }
//    ),
//    suite("strings")(
//      testM("verify(m, sign(m)) = true") {
//        checkM(Gen.anyASCIIString) { m =>
//          for {
//            k        <- HMAC.genKey(alg)
//            hmac     <- HMAC.sign(m, k, alg, US_ASCII)
//            verified <- HMAC.verify(m, hmac, k, alg, US_ASCII)
//          } yield assert(verified)(isTrue)
//        }
//      },
//      testM("verify(m1, sign(m0)) = false") {
//        checkM(Gen.anyASCIIString, Gen.anyASCIIString) {
//          case (m0, m1) if m0 != m1 =>
//            for {
//              k        <- HMAC.genKey(alg)
//              hmac     <- HMAC.sign(m1, k, alg, US_ASCII)
//              verified <- HMAC.verify(m0, hmac, k, alg, US_ASCII)
//            } yield assert(verified)(isFalse)
//          case _ => assertCompletesM
//        }
//      }
//    ),
    suite("bytes")(
      testM("verify(m, sign(m)) = true") {
        checkM(Gen.listOf(Gen.anyByte)) { m =>
          for {
            k         <- Signature.genKey(alg)
            signature <- Signature.sign(m.toArray, k.getPrivate)
            verified  <- Signature.verify(m.toArray, signature, k.getPublic)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m1, sign(m0)) = false") {
        checkM(Gen.listOf(Gen.anyByte), Gen.listOf(Gen.anyByte)) {
          case (m0, m1) if m0 != m1 =>
            for {
              k         <- Signature.genKey(alg)
              signature <- Signature.sign(m0.toArray, k.getPrivate)
              verified  <- Signature.verify(m1.toArray, signature, k.getPublic)
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
  ).provideSomeLayer[Environment](Signature.live ++ SecureRandom.live.orDie)
}
