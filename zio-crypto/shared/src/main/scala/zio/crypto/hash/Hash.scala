package zio.crypto.hash

import java.nio.charset.Charset
import java.security.{ MessageDigest => JMessageDigest }

import scala.annotation.implicitNotFound

import zio._
import zio.crypto.{ ByteHelpers, Secure }

sealed trait HashAlgorithm

object HashAlgorithm {

  case object SHA256 extends HashAlgorithm {
    implicit val secure: Secure[SHA256] = new Secure[SHA256] {}
    implicit val self: SHA256           = SHA256
  }

  case object SHA512 extends HashAlgorithm {
    implicit val secure: Secure[SHA512] = new Secure[SHA512] {}
    implicit val self: SHA512           = SHA512
  }

  case object MD5 extends HashAlgorithm {
    implicit val self: MD5 = MD5
  }

  case object SHA1 extends HashAlgorithm {
    implicit val self: SHA1 = SHA1
  }

  type SHA256 = SHA256.type
  type SHA512 = SHA512.type
  type MD5    = MD5.type
  type SHA1   = SHA1.type
}

case class MessageDigest[T](value: T) extends AnyVal

object Hash {

  type Hash = Has[Hash.Service]

  trait Service {

    def hash[Alg <: HashAlgorithm](m: Chunk[Byte])(implicit
      secure: Secure[Alg],
      alg: Alg
    ): MessageDigest[Chunk[Byte]]

    def verify[Alg <: HashAlgorithm](m: Chunk[Byte], digest: MessageDigest[Chunk[Byte]])(implicit
      secure: Secure[Alg],
      alg: Alg
    ): Boolean

    def hash[Alg <: HashAlgorithm](m: String, charset: Charset)(implicit
      secure: Secure[Alg],
      alg: Alg
    ): MessageDigest[String]

    def verify[Alg <: HashAlgorithm](m: String, digest: MessageDigest[String], charset: Charset)(implicit
      secure: Secure[Alg],
      alg: Alg
    ): Boolean
  }

  val live: ULayer[Hash] = ZLayer.succeed(new Service {

    private def getAlgorithmName(alg: HashAlgorithm) = alg match {
      case HashAlgorithm.MD5    => "MD5"
      case HashAlgorithm.SHA1   => "SHA-1"
      case HashAlgorithm.SHA256 => "SHA-256"
      case HashAlgorithm.SHA512 => "SHA-512"
    }

    override def hash[Alg <: HashAlgorithm](m: String, charset: Charset)(implicit
      secure: Secure[Alg],
      alg: Alg
    ): MessageDigest[String] =
      MessageDigest(
        ByteHelpers.toB64String(
          hash(m =
            Chunk.fromArray(
              // May throw CharacterCodingException
              m.getBytes(charset)
            )
          ).value
        )
      )

    override def verify[Alg <: HashAlgorithm](
      m: String,
      digest: MessageDigest[String],
      charset: Charset
    )(implicit secure: Secure[Alg], alg: Alg): Boolean =
      ByteHelpers
        .fromB64String(digest.value)
        .map(MessageDigest.apply)
        .exists(d =>
          verify(
            m = Chunk.fromArray(
              // May throw CharacterCodingException
              m.getBytes(charset)
            ),
            digest = d
          )
        )

    override def hash[Alg <: HashAlgorithm](m: Chunk[Byte])(implicit
      secure: Secure[Alg],
      alg: Alg
    ): MessageDigest[Chunk[Byte]] =
      MessageDigest(
        Chunk.fromArray(
          JMessageDigest
            // May throw NoSuchAlgorithmException
            .getInstance(getAlgorithmName(alg))
            .digest(m.toArray)
        )
      )

    override def verify[Alg <: HashAlgorithm](m: Chunk[Byte], digest: MessageDigest[Chunk[Byte]])(implicit
      secure: Secure[Alg],
      alg: Alg
    ): Boolean =
      JMessageDigest.isEqual(hash(m).value.toArray, digest.value.toArray)

  })

  /**
   * Hashes the message `m` using the algorithm `alg`.
   * @param m the message to hash.
   * @return the computed hash.
   */
  def hash[Alg <: HashAlgorithm](m: Chunk[Byte])(implicit
    @implicitNotFound(
      "You're using an unsecure algorithm! If this is what you want, use the `unsecure` function as follows: \n  " +
        "unsecure(implicit secure => Hash.hash(m))"
    ) secure: Secure[Alg],
    alg: Alg
  ): RIO[Hash, MessageDigest[Chunk[Byte]]] =
    ZIO.access(_.get.hash(m))

  /**
   * Verifies that the hash `digest` is the valid hash of the message `m`.
   * Returns true if `hash(m)` matches `digest`.
   *
   * @param m the message that you'd like to check
   * @param digest the digest to test for m
   * @return a boolean indiciating whether `hash(m) == digest`
   */
  def verify[Alg <: HashAlgorithm](
    m: Chunk[Byte],
    digest: MessageDigest[Chunk[Byte]]
  )(implicit
    @implicitNotFound(
      "You're using an unsecure algorithm! If this is what you want, use the `unsecure` function as follows: \n  " +
        "unsecure(implicit secure => Hash.verify(m))"
    )
    secure: Secure[Alg],
    alg: Alg
  ): RIO[Hash, Boolean] =
    ZIO.access(_.get.verify(m, digest))

  /**
   * Hashes the message `m` using the algorithm `alg`.
   * @param m the message to hash. Encoded using `charset`.
   * @return the computed hash.
   */
  def hash[Alg <: HashAlgorithm](m: String, charset: Charset)(implicit
    @implicitNotFound(
      "You're using an unsecure algorithm! If this is what you want, use the `unsecure` function as follows: \n  " +
        "unsecure(implicit secure => Hash.hash(m))"
    ) secure: Secure[Alg],
    alg: Alg
  ): RIO[Hash, MessageDigest[String]] =
    ZIO.access(_.get.hash(m, charset))

  /**
   * Verifies that the hash `digest` is the valid hash of the message `m`.
   * Returns true if `hash(m)` matches `digest`.
   *
   * @param m the message that you'd like to check, encoded using `charset`.
   * @param digest the digest to test for m
   * @return a boolean indiciating whether `hash(m) == digest`
   */
  def verify[Alg <: HashAlgorithm](m: String, digest: MessageDigest[String], charset: Charset)(implicit
    @implicitNotFound(
      "You're using an unsecure algorithm! If this is what you want, use the `unsecure` function as follows: \n  " +
        "unsecure(implicit secure => Hash.verify(m))"
    )
    secure: Secure[Alg],
    alg: Alg
  ): RIO[Hash, Boolean] =
    ZIO.access(_.get.verify(m, digest, charset))

}
