package zio.crypto.hash

import java.nio.charset.StandardCharsets.US_ASCII

import zio._
import zio.crypto.{ Secure, unsecure }
import zio.test.Assertion._
import zio.test._
import zio.Random
import zio.test.{ Gen, Sized, ZIOSpecDefault }

object HashSpec extends ZIOSpecDefault {

  private val genByteChunk: Gen[Random with Sized, Chunk[Byte]] = Gen.chunkOf(Gen.byte)

  private def testAlgorithm[Alg <: HashAlgorithm](implicit alg: Alg, secure: Secure[Alg]) = suite(alg.toString)(
    suite("bytes")(
      test("verify(m, hash(m)) = true") {
        check(genByteChunk) { m =>
          for {
            digest   <- Hash.hash(m = m)
            verified <- Hash.verify(m = m, digest = digest)
          } yield assert(verified)(isTrue)
        }
      },
      test("verify(m, 'garbage') = false") {
        check(genByteChunk, genByteChunk) { (m0, m1) =>
          assertM(Hash.verify(m = m0, digest = MessageDigest(m1)))(isFalse)
        }
      },
      test("verify(m0, hash(m1)) = false") {
        check(genByteChunk, genByteChunk) {
          case (m0, m1) if m0 != m1 =>
            for {
              digest   <- Hash.hash(m0)
              verified <- Hash.verify(m = m1, digest = digest)
            } yield assert(verified)(isFalse)
          case _                    => assertCompletesM
        }
      }
    ),
    suite("strings")(
      test("verify(m, hash(m)) = true") {
        check(Gen.asciiString) { m =>
          for {
            digest   <- Hash.hash(m, US_ASCII)
            verified <- Hash.verify(m = m, digest = digest, US_ASCII)
          } yield assert(verified)(isTrue)
        }
      },
      test("verify(m, 'garbage') = false") {
        check(Gen.asciiString, Gen.asciiString) { (m0, m1) =>
          assertM(Hash.verify(m = m0, digest = MessageDigest(m1), US_ASCII))(isFalse)
        }
      },
      test("verify(m0, hash(m1)) = false") {
        check(Gen.asciiString, Gen.asciiString) {
          case (m0, m1) if m0 != m1 =>
            for {
              digest   <- Hash.hash(m0, US_ASCII)
              verified <- Hash.verify(m = m1, digest = digest, US_ASCII)
            } yield assert(verified)(isFalse)
          case _                    => assertCompletesM
        }
      }
    )
  )

  def spec: Spec[Environment, TestFailure[Throwable], TestSuccess] = suite("HashSpec")(
    unsecure(implicit s => testAlgorithm[HashAlgorithm.MD5]),
    unsecure(implicit s => testAlgorithm[HashAlgorithm.SHA1]),
    testAlgorithm[HashAlgorithm.SHA256],
    testAlgorithm[HashAlgorithm.SHA512]
  ).provideCustomLayer(Hash.live)

}
