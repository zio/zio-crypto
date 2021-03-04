package zio.crypto.mac

import java.nio.charset.StandardCharsets.US_ASCII

import zio._
import zio.crypto.keyset.KeysetManager
import zio.random.Random
import zio.test.Assertion._
import zio.test._

object MACSpec extends DefaultRunnableSpec {
  private val assertCompletesM                                  = assertM(UIO.succeed(true))(isTrue)
  private val genByteChunk: Gen[Random with Sized, Chunk[Byte]] = Gen.chunkOf(Gen.anyByte)

  private def testAlgorithm(alg: MACAlgorithm) = suite(alg.toString)(
    suite("strings")(
      testM("verify(m, sign(m, k), k) = true") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            k        <- KeysetManager.generateNewSymmetric(alg)
            mac      <- MAC.sign(m, k, US_ASCII)
            verified <- MAC.verify(m, mac, k, US_ASCII)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m, 'garbage', k) = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) { (m0, m1) =>
          for {
            k        <- KeysetManager.generateNewSymmetric(alg)
            verified <- MAC.verify(m0, MACObject(m1), k, US_ASCII)
          } yield assert(verified)(isFalse)
        }
      },
      testM("verify(m1, sign(m1, k0), k1) = false") {
        checkM(Gen.anyASCIIString) { m =>
          for {
            k0       <- KeysetManager.generateNewSymmetric(alg)
            k1       <- KeysetManager.generateNewSymmetric(alg)
            mac      <- MAC.sign(m, k0, US_ASCII)
            verified <- MAC.verify(m, mac, k1, US_ASCII)
          } yield assert(verified)(isFalse)
        }
      },
      testM("verify(m1, sign(m0, k), k) = false") {
        checkM(Gen.anyASCIIString, Gen.anyASCIIString) {
          case (m0, m1) if m0 != m1 =>
            for {
              k        <- KeysetManager.generateNewSymmetric(alg)
              mac      <- MAC.sign(m1, k, US_ASCII)
              verified <- MAC.verify(m0, mac, k, US_ASCII)
            } yield assert(verified)(isFalse)
          case _ => assertCompletesM
        }
      }
    ),
    suite("bytes")(
      testM("verify(m, sign(m, k), k) = true") {
        checkM(genByteChunk) { m =>
          for {
            k        <- KeysetManager.generateNewSymmetric(alg)
            mac      <- MAC.sign(m, k)
            verified <- MAC.verify(m, mac, k)
          } yield assert(verified)(isTrue)
        }
      },
      testM("verify(m1, 'garbage', k) = false") {
        checkM(genByteChunk, genByteChunk) { (m0, m1) =>
          for {
            k        <- KeysetManager.generateNewSymmetric(alg)
            verified <- MAC.verify(m0, MACObject(m1), k)
          } yield assert(verified)(isFalse)
        }
      },
      testM("verify(m1, sign(m1, k0), k1) = false") {
        checkM(genByteChunk) { m =>
          for {
            k0       <- KeysetManager.generateNewSymmetric(alg)
            k1       <- KeysetManager.generateNewSymmetric(alg)
            mac      <- MAC.sign(m, k0)
            verified <- MAC.verify(m, mac, k1)
          } yield assert(verified)(isFalse)
        }
      },
      testM("verify(m1, sign(m0, k), k) = false") {
        checkM(genByteChunk, genByteChunk) {
          case (m0, m1) if m0 != m1 =>
            for {
              k        <- KeysetManager.generateNewSymmetric(alg)
              mac      <- MAC.sign(m1, k)
              verified <- MAC.verify(m0, mac, k)
            } yield assert(verified)(isFalse)
          case _ => assertCompletesM
        }
      }
    )
  )

  def spec: Spec[Environment, TestFailure[Throwable], TestSuccess] = suite("MACSpec")(
    testAlgorithm(MACAlgorithm.HMACSHA256),
    testAlgorithm(MACAlgorithm.HMACSHA256HalfDigest),
    testAlgorithm(MACAlgorithm.HMACSHA512),
    testAlgorithm(MACAlgorithm.HMACSHA512HalfDigest),
    testAlgorithm(MACAlgorithm.AES256CMAC)
  ).provideCustomLayer(MAC.live.orDie ++ KeysetManager.live)
}
