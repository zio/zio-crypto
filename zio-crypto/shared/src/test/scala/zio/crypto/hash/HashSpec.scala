package zio.crypto.hash

import java.nio.charset.StandardCharsets.US_ASCII
import zio.{ Chunk, UIO }
import zio.random.Random
import zio.test.Assertion._
import zio.test._

object HashSpec extends DefaultRunnableSpec {

  private val assertCompletesM = assertM(UIO(true))(isTrue)

  private val genByteChunk: Gen[Random with Sized, Chunk[Byte]] = Gen.chunkOf(Gen.anyByte)

  private def testAlgorithm(alg: HashAlgorithm) = suite(alg.toString)(
    suite("bytes")(
      testM("verify(m, hash(m)) = true") {
        checkM(genByteChunk) { m =>
          for {
            digest   <- Hash.hash(m = m, alg = alg)
            verified <- Hash.verify(m = m, digest = digest, alg = alg)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m, 'garbage') = false") {
        checkM(genByteChunk, genByteChunk) { (m0, m1) =>
          assertM(Hash.verify(m = m0, digest = MessageDigest(m1), alg = alg))(isFalse)
        }
      },
      testM("verify(m0, hash(m1)) = false") {
        checkM(genByteChunk, genByteChunk) {
          case (m0, m1) if m0 != m1 =>
            for {
              digest   <- Hash.hash(m0, alg)
              verified <- Hash.verify(m = m1, digest = digest, alg = alg)
            } yield assert(verified)(isFalse)
          case _ => assertCompletesM
        }
      }
    ),
    suite("strings")(
      testM("verify(m, hash(m)) = true") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            digest   <- Hash.hash(m, alg, US_ASCII)
            verified <- Hash.verify(m = m, digest = digest, alg = alg, US_ASCII)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m, 'garbage') = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) { (m0, m1) =>
          assertM(Hash.verify(m = m0, digest = MessageDigest(m1), alg = alg, US_ASCII))(isFalse)
        }
      },
      testM("verify(m0, hash(m1)) = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) {
          case (m0, m1) if m0 != m1 =>
            for {
              digest   <- Hash.hash(m0, alg, US_ASCII)
              verified <- Hash.verify(m = m1, digest = digest, alg = alg, US_ASCII)
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
  ).provideCustomLayer(Hash.live)
}
