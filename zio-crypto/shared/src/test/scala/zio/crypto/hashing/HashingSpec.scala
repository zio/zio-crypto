package zio.crypto.hashing

import java.nio.charset.StandardCharsets.US_ASCII
import zio.UIO
import zio.test.Assertion._
import zio.test._

object HashingSpec extends DefaultRunnableSpec {

  private val assertCompletesM = assertM(UIO(true))(isTrue)

  private def testAlgorithm(algorithm: HashAlgorithm) = suite(algorithm.toString)(
    suite("bytes")(
      testM("verify(m, hash(m)) = true") {
        checkM(Gen.listOf(Gen.anyByte)) { m =>
          for {
            digest   <- Hashing.hash(m, algorithm)
            verified <- Hashing.verify(m = m, digest = digest, alg = algorithm)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m, 'garbage') = false") {
        checkM(Gen.listOf(Gen.anyByte), Gen.listOf(Gen.anyByte)) { (m0, m1) =>
          assertM(Hashing.verify(m = m0, digest = MessageDigest(m1), alg = algorithm))(isFalse)
        }
      },
      testM("verify(m0, hash(m1)) = false") {
        checkM(Gen.listOf(Gen.anyByte), Gen.listOf(Gen.anyByte)) {
          case (m0, m1) if m0 != m1 =>
            for {
              digest   <- Hashing.hash(m0, algorithm)
              verified <- Hashing.verify(m = m1, digest = digest, alg = algorithm)
            } yield assert(verified)(isFalse)
          case _ => assertCompletesM
        }
      }
    ),
    suite("strings")(
      testM("verify(m, hash(m)) = true") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            digest   <- Hashing.hash(m, algorithm, US_ASCII)
            verified <- Hashing.verify(m = m, digest = digest, alg = algorithm, US_ASCII)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m, 'garbage') = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) { (m0, m1) =>
          assertM(Hashing.verify(m = m0, digest = MessageDigest(m1), alg = algorithm, US_ASCII))(isFalse)
        }
      },
      testM("verify(m0, hash(m1)) = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) {
          case (m0, m1) if m0 != m1 =>
            for {
              digest   <- Hashing.hash(m0, algorithm, US_ASCII)
              verified <- Hashing.verify(m = m1, digest = digest, alg = algorithm, US_ASCII)
            } yield assert(verified)(isFalse)
          case _ => assertCompletesM
        }
      }
    )
  )

  def spec: Spec[Environment, TestFailure[Throwable], TestSuccess] = suite("HashingSpec")(
    testAlgorithm(HashAlgorithm.MD5),
    testAlgorithm(HashAlgorithm.SHA1),
    testAlgorithm(HashAlgorithm.SHA256),
    testAlgorithm(HashAlgorithm.SHA512)
  ).provideCustomLayer(Hashing.live)
}
