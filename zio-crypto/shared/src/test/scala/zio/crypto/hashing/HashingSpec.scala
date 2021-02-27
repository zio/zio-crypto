package zio.crypto.hashing

import java.nio.charset.StandardCharsets.US_ASCII
import zio.UIO
import zio.random.Random
import zio.test.Assertion._
import zio.test._

object HashingSpec extends DefaultRunnableSpec {

  private val assertCompletesM = assertM(UIO(true))(isTrue)

  private val genByteArray: Gen[Random with Sized, Array[Byte]] = Gen.listOf(Gen.anyByte).map(_.toArray)

  private def testAlgorithm(alg: HashAlgorithm) = suite(alg.toString)(
    suite("bytes")(
      testM("verify(m, hash(m)) = true") {
        checkM(genByteArray) { m =>
          for {
            digest   <- Hashing.hash(m = m, alg = alg)
            verified <- Hashing.verify(m = m, digest = digest, alg = alg)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m, 'garbage') = false") {
        checkM(genByteArray, genByteArray) { (m0, m1) =>
          assertM(Hashing.verify(m = m0, digest = MessageDigest(m1), alg = alg))(isFalse)
        }
      },
      testM("verify(m0, hash(m1)) = false") {
        checkM(genByteArray, genByteArray) {
          case (m0, m1) if !m0.sameElements(m1) =>
            for {
              digest   <- Hashing.hash(m0, alg)
              verified <- Hashing.verify(m = m1, digest = digest, alg = alg)
            } yield assert(verified)(isFalse)
          case _ => assertCompletesM
        }
      }
    ),
    suite("strings")(
      testM("verify(m, hash(m)) = true") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            digest   <- Hashing.hash(m, alg, US_ASCII)
            verified <- Hashing.verify(m = m, digest = digest, alg = alg, US_ASCII)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m, 'garbage') = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) { (m0, m1) =>
          assertM(Hashing.verify(m = m0, digest = MessageDigest(m1), alg = alg, US_ASCII))(isFalse)
        }
      },
      testM("verify(m0, hash(m1)) = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) {
          case (m0, m1) if m0 != m1 =>
            for {
              digest   <- Hashing.hash(m0, alg, US_ASCII)
              verified <- Hashing.verify(m = m1, digest = digest, alg = alg, US_ASCII)
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
