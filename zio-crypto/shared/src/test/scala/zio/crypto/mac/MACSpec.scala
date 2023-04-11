package zio.crypto.mac

import java.nio.charset.StandardCharsets.US_ASCII

import zio._
import zio.crypto.keyset.KeysetManager
import zio.test._

object MACSpec extends ZIOSpecDefault {
  private val genByteChunk: Gen[Sized, Chunk[Byte]] = Gen.chunkOf(Gen.byte)

  private def testAlgorithm(alg: MACAlgorithm) = suite(alg.toString)(
    suite("strings")(
      test("verify(m, sign(m, k), k) = true") {
        check(Gen.asciiString) { m =>
          for {
            k        <- KeysetManager.generateNewSymmetric(alg)
            mac      <- MAC.sign(m, k, US_ASCII)
            verified <- MAC.verify(m, mac, k, US_ASCII)
          } yield assertTrue(verified)
        }
      },
      test("verify(m, 'garbage', k) = false") {
        check(Gen.asciiString, Gen.asciiString) { (m0, m1) =>
          for {
            k        <- KeysetManager.generateNewSymmetric(alg)
            verified <- MAC.verify(m0, MACObject(m1), k, US_ASCII)
          } yield assertTrue(!verified)
        }
      },
      test("verify(m1, sign(m1, k0), k1) = false") {
        check(Gen.asciiString) { m =>
          for {
            k0       <- KeysetManager.generateNewSymmetric(alg)
            k1       <- KeysetManager.generateNewSymmetric(alg)
            mac      <- MAC.sign(m, k0, US_ASCII)
            verified <- MAC.verify(m, mac, k1, US_ASCII)
          } yield assertTrue(!verified)
        }
      },
      test("verify(m1, sign(m0, k), k) = false") {
        check(Gen.asciiString, Gen.asciiString) {
          case (m0, m1) if m0 != m1 =>
            for {
              k        <- KeysetManager.generateNewSymmetric(alg)
              mac      <- MAC.sign(m1, k, US_ASCII)
              verified <- MAC.verify(m0, mac, k, US_ASCII)
            } yield assertTrue(!verified)
          case _                    => assertCompletesZIO
        }
      }
    ),
    suite("bytes")(
      test("verify(m, sign(m, k), k) = true") {
        check(genByteChunk) { m =>
          for {
            k        <- KeysetManager.generateNewSymmetric(alg)
            mac      <- MAC.sign(m, k)
            verified <- MAC.verify(m, mac, k)
          } yield assertTrue(verified)
        }
      },
      test("verify(m1, 'garbage', k) = false") {
        check(genByteChunk, genByteChunk) { (m0, m1) =>
          for {
            k        <- KeysetManager.generateNewSymmetric(alg)
            verified <- MAC.verify(m0, MACObject(m1), k)
          } yield assertTrue(!verified)
        }
      },
      test("verify(m1, sign(m1, k0), k1) = false") {
        check(genByteChunk) { m =>
          for {
            k0       <- KeysetManager.generateNewSymmetric(alg)
            k1       <- KeysetManager.generateNewSymmetric(alg)
            mac      <- MAC.sign(m, k0)
            verified <- MAC.verify(m, mac, k1)
          } yield assertTrue(!verified)
        }
      },
      test("verify(m1, sign(m0, k), k) = false") {
        check(genByteChunk, genByteChunk) {
          case (m0, m1) if m0 != m1 =>
            for {
              k        <- KeysetManager.generateNewSymmetric(alg)
              mac      <- MAC.sign(m1, k)
              verified <- MAC.verify(m0, mac, k)
            } yield assertTrue(!verified)
          case _                    => assertCompletesZIO
        }
      }
    )
  )

  def spec: Spec[TestEnvironment with Scope, Any] = suite("MACSpec")(
    testAlgorithm(MACAlgorithm.HMACSHA256),
    testAlgorithm(MACAlgorithm.HMACSHA256HalfDigest),
    testAlgorithm(MACAlgorithm.HMACSHA512),
    testAlgorithm(MACAlgorithm.HMACSHA512HalfDigest),
    testAlgorithm(MACAlgorithm.AES256CMAC)
  ).provideLayer(MAC.live.orDie ++ KeysetManager.live)
}
