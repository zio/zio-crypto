package zio.crypto.random

import zio._
import zio.crypto.ByteHelpers

import java.security.{ NoSuchAlgorithmException, SecureRandom => JSecureRandom }

object SecureRandom {

  type SecureRandom = Has[SecureRandom.Service]

  trait Service {
    def nextBytes(length: Int): Task[Seq[Byte]]
    def nextString(entropyBytes: Int): Task[String]
    def setSeed(seed: Long): UIO[Unit]
    def getJavaSecureRandom: UIO[JSecureRandom]
  }

  private val UnixURandom = "NativePRNGNonBlocking"

  val live: Layer[NoSuchAlgorithmException, SecureRandom] = (for {
    r <- Task.effect(JSecureRandom.getInstance(UnixURandom)).mapError {
           case e: NoSuchAlgorithmException => e
           case e =>
             new NoSuchAlgorithmException(
               s"Could not create algorithm $UnixURandom",
               e
             )
         }
    /*
     * Seed the SecureRandom properly as per
     * [[https://tersesystems.com/2015/12/17/the-right-way-to-use-securerandom/]]
     */
    _ <- UIO.effectTotal(r.nextBytes(new Array[Byte](20)))
  } yield r)
    .map(rand =>
      new Service {

        def nextBytes(length: Int): Task[Seq[Byte]] =
          length match {
            case x if x < 0 =>
              IO.fail(new IllegalArgumentException(s"Requested $length bytes < 0 for random bytes"))
            case _ =>
              UIO.effectTotal {
                val array = Array.ofDim[Byte](length)
                rand.nextBytes(array)
                array
              }
          }

        def nextString(entropyBytes: Int): Task[String] =
          nextBytes(entropyBytes).map(ByteHelpers.toB64String)

        def setSeed(seed: Long): UIO[Unit] =
          UIO.effectTotal(rand.setSeed(seed))

        override def getJavaSecureRandom: UIO[JSecureRandom] = UIO(rand)
      }
    )
    .toLayer

  /**
   * Generates a pseudo-random sequence of bytes of the specified length.
   *
   * @param length the requested length of the resulting `Seq[Byte]`.
   * @return a `Seq[Byte]` of length `length`
   */
  def nextBytes(length: => Int): RIO[SecureRandom, Seq[Byte]] =
    ZIO.accessM(_.get.nextBytes(length))

  /**
   * Generates a base64-encoded pseudo-random string with `entropyBytes` bytes
   * of entropy. The resulting string will longer than `entropyBytes`
   * (or empty when `entropyBytes` is 0), as the base64 encoding requires
   * additional space.
   *
   * @param entropyBytes the number of bytes of entropy to include in the returned
   *                     `String`.
   * @return a `String` with at least `entropyBytes` of entropy.
   */
  def nextString(entropyBytes: => Int): RIO[SecureRandom, String] =
    ZIO.accessM(_.get.nextString(entropyBytes))

  /**
   * Reseeds this random object, using the eight bytes contained
   * in the given `seed`. The given seed supplements,
   * rather than replaces, the existing seed. Thus, repeated calls
   * are guaranteed never to reduce randomness.
   *
   * This method is defined for compatibility with
   * `java.util.Random`.
   *
   * @param seed the seed.
   */
  def setSeed(seed: => Long): URIO[SecureRandom, Unit] =
    ZIO.accessM(_.get.setSeed(seed))

  /**
   * Exposes the underlying `java.security.SecureRandom`
   * used internally.
   *
   * @return a `java.security.SecureRandom` that backs this `SecureRandom`.
   */
  def getJavaSecureRandom: URIO[SecureRandom, JSecureRandom] =
    ZIO.accessM(_.get.getJavaSecureRandom)

}
