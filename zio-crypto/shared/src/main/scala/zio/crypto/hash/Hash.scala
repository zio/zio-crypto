package zio.crypto.hash

import zio._
import zio.crypto.ByteHelpers

import java.nio.charset.Charset
import java.security.{ MessageDigest => JMessageDigest }

sealed class HashAlgorithm(val name: String)

object HashAlgorithm {
  case object SHA256 extends HashAlgorithm("SHA-256")
  case object SHA512 extends HashAlgorithm("SHA-512")

  // DO NOT USE IN A SECURE CONTEXT
  case object MD5 extends HashAlgorithm("MD5")
  // DO NOT USE IN A SECURE CONTEXT
  case object SHA1 extends HashAlgorithm("SHA-1")
}

case class MessageDigest[T](value: T) extends AnyVal

object Hash {

  type Hash = Has[Hash.Service]

  trait Service {
    def hash(m: Chunk[Byte], alg: HashAlgorithm): Task[MessageDigest[Chunk[Byte]]]
    def verify(m: Chunk[Byte], digest: MessageDigest[Chunk[Byte]], alg: HashAlgorithm): Task[Boolean]

    def hash(m: String, alg: HashAlgorithm, charset: Charset): Task[MessageDigest[String]]
    def verify(m: String, digest: MessageDigest[String], alg: HashAlgorithm, charset: Charset): Task[Boolean]
  }

  val live: ULayer[Hash] = ZLayer.succeed(new Service {

    override def hash(m: String, alg: HashAlgorithm, charset: Charset): Task[MessageDigest[String]] =
      hash(
        m = Chunk.fromArray(m.getBytes(charset)),
        alg = alg
      )
        .map(_.value)
        .map(ByteHelpers.toB64String)
        .map(MessageDigest.apply)

    override def verify(
      m: String,
      digest: MessageDigest[String],
      alg: HashAlgorithm,
      charset: Charset
    ): Task[Boolean] =
      ByteHelpers
        .fromB64String(digest.value)
        .foldM(
          // If the base-64 decoding fails, this can't be a correct message
          _ => UIO(false),
          digest => verify(m = Chunk.fromArray(m.getBytes(charset)), MessageDigest(digest), alg = alg)
        )

    override def hash(m: Chunk[Byte], alg: HashAlgorithm): Task[MessageDigest[Chunk[Byte]]] =
      Task
        .effect(JMessageDigest.getInstance(alg.name).digest(m.toArray))
        .map(Chunk.fromArray)
        .map(MessageDigest.apply)

    override def verify(m: Chunk[Byte], digest: MessageDigest[Chunk[Byte]], alg: HashAlgorithm): Task[Boolean] =
      hash(m = m, alg = alg)
        .map(digest1 => JMessageDigest.isEqual(digest1.value.toArray, digest.value.toArray))

  })

  /**
   * Hashes the message `m` using the algorithm `alg`.
   * @param m the message to hash.
   * @param alg the algorithm to use in hashing.
   *
   * @return the computed hash.
   */
  def hash(m: Chunk[Byte], alg: HashAlgorithm): RIO[Hash, MessageDigest[Chunk[Byte]]] =
    ZIO.accessM(_.get.hash(m, alg))

  /**
   * Verifies that the hash `digest` is the valid hash of the message `m`.
   * Returns true if `hash(m)` matches `digest`.
   *
   * @param m the message that you'd like to check
   * @param digest the digest to test for m
   * @param alg the algorithm used in hashing the digest
   * @return a boolean indiciating whether `hash(m) == digest`
   */
  def verify(m: Chunk[Byte], digest: MessageDigest[Chunk[Byte]], alg: HashAlgorithm): RIO[Hash, Boolean] =
    ZIO.accessM(_.get.verify(m, digest, alg))

  /**
   * Hashes the message `m` using the algorithm `alg`.
   * @param m the message to hash. Encoded using `charset`.
   * @param alg the algorithm to use in hashing.
   *
   * @return the computed hash.
   */
  def hash(m: String, alg: HashAlgorithm, charset: Charset): RIO[Hash, MessageDigest[String]] =
    ZIO.accessM(_.get.hash(m, alg, charset))

  /**
   * Verifies that the hash `digest` is the valid hash of the message `m`.
   * Returns true if `hash(m)` matches `digest`.
   *
   * @param m the message that you'd like to check, encoded using `charset`.
   * @param digest the digest to test for m
   * @param alg the algorithm used in hashing the digest
   * @return a boolean indiciating whether `hash(m) == digest`
   */
  def verify(m: String, digest: MessageDigest[String], alg: HashAlgorithm, charset: Charset): RIO[Hash, Boolean] =
    ZIO.accessM(_.get.verify(m, digest, alg, charset))

}
