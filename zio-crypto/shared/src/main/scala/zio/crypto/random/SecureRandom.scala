package zio.crypto.random

import java.security.{ NoSuchAlgorithmException, SecureRandom => JSecureRandom }

import zio._
import zio.crypto.ByteHelpers

object SecureRandom {

  type SecureRandom = Has[SecureRandom.Service]

  trait Service {
    def nextBytes(length: Int): Task[Chunk[Byte]]
    def nextString(entropyBytes: Int): Task[String]
    def setSeed(seed: Long): UIO[Unit]
    def execute[A](fn: JSecureRandom => A): Task[A]
  }

  val live: Layer[NoSuchAlgorithmException, SecureRandom] = (for {
    // Java's SecureRandom can be a major source of lock contention.
    // Tink wraps Java's SecureRandom in a ThreadLocal to solve this problem.
    // https://github.com/google/tink/issues/72
    randomRef <- FiberRef.make[JSecureRandom](new JSecureRandom())

    // Force seeding
    // The returned SecureRandom object has not been seeded.
    // To seed the returned object, call the setSeed method.
    // If setSeed is not called, the first call to nextBytes
    // will force the SecureRandom object to seed itself.
    // This self-seeding will not occur if setSeed was previously called.
    // https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html
    _ <- randomRef.get.map(_.nextLong())
  } yield randomRef)
    .map(randomRef =>
      new Service {
        override def nextBytes(length: Int): Task[Chunk[Byte]] =
          length match {
            case x if x < 0 =>
              IO.fail(new IllegalArgumentException(s"Requested $length bytes < 0 for random bytes"))
            case _          =>
              randomRef.get.map { r =>
                val array = Array.ofDim[Byte](length)
                r.nextBytes(array)
                Chunk.fromArray(array)
              }
          }

        override def nextString(entropyBytes: Int): Task[String] =
          nextBytes(entropyBytes).map(ByteHelpers.toB64String)

        override def setSeed(seed: Long): UIO[Unit] =
          randomRef.get.map(_.setSeed(seed))

        override def execute[A](fn: JSecureRandom => A): Task[A] =
          randomRef.get.map(fn)
      }
    )
    .toLayer

  /**
   * Generates a pseudo-random Arrayuence of bytes of the specified length.
   *
   * @param length the requested length of the resulting `Chunk[Byte]`.
   * @return a `Chunk[Byte]` of length `length`
   */
  def nextBytes(length: => Int): RIO[SecureRandom, Chunk[Byte]] =
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
   * Provides the underlying `java.security.SecureRandom`
   * used internally to the function `fn`.
   *
   * @param fn: A function taking a `java.security.SecureRandom`
   * @return the value returned by `fn`
   */
  def execute[A](fn: JSecureRandom => A): RIO[SecureRandom, A] =
    ZIO.accessM(_.get.execute(fn))

}
