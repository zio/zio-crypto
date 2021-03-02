package zio.crypto.mac

import java.nio.charset.Charset
import java.security.MessageDigest
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{ KeyGenerator, Mac, SecretKey }

import zio._
import zio.crypto.ByteHelpers

sealed trait HMACAlgorithm

object HMACAlgorithm {
  case object HMACSHA1   extends HMACAlgorithm
  case object HMACSHA256 extends HMACAlgorithm
  case object HMACSHA384 extends HMACAlgorithm
  case object HMACSHA512 extends HMACAlgorithm
}

final case class HMACSerializedKey(value: String)     extends AnyVal
final case class HMACSecretKey(underlying: SecretKey) extends AnyVal
final case class HMACObject[Kind](value: Kind)        extends AnyVal

object HMAC {

  type HMAC = Has[HMAC.Service]

  trait Service {
    def sign(m: Chunk[Byte], k: HMACSecretKey): HMACObject[Chunk[Byte]]
    def verify(m: Chunk[Byte], hmac: HMACObject[Chunk[Byte]], k: HMACSecretKey): Boolean

    def sign(m: String, k: HMACSecretKey, charset: Charset): HMACObject[String]
    def verify(m: String, hmac: HMACObject[String], k: HMACSecretKey, charset: Charset): Boolean

    def genKey(alg: HMACAlgorithm): Task[HMACSecretKey]
    def serializeKey(k: HMACSecretKey): HMACSerializedKey
    def deserializeKey(k: HMACSerializedKey): Option[HMACSecretKey]
  }

  val live: ULayer[HMAC] = ZLayer.succeed(new Service {

    private def getAlgorithmName(alg: HMACAlgorithm) = alg match {
      case HMACAlgorithm.HMACSHA1   => "HmacSHA1"
      case HMACAlgorithm.HMACSHA256 => "HmacSHA256"
      case HMACAlgorithm.HMACSHA384 => "HmacSHA384"
      case HMACAlgorithm.HMACSHA512 => "HmacSHA512"
    }

    override def sign(m: Chunk[Byte], k: HMACSecretKey): HMACObject[Chunk[Byte]] = {
      // May throw NoSuchAlgorithmException
      val instance = Mac.getInstance(k.underlying.getAlgorithm)
      // May throw InvalidKeyException
      instance.init(k.underlying)
      HMACObject(Chunk.fromArray(instance.doFinal(m.toArray)))
    }

    override def verify(m: Chunk[Byte], hmac: HMACObject[Chunk[Byte]], k: HMACSecretKey): Boolean =
      MessageDigest.isEqual(sign(m = m, k = k).value.toArray, hmac.value.toArray)

    override def sign(m: String, k: HMACSecretKey, charset: Charset): HMACObject[String] =
      HMACObject(
        ByteHelpers.toB64String(
          sign(
            m = Chunk.fromArray(
              // May throw CharacterCodingException
              m.getBytes(charset)
            ),
            k = k
          ).value
        )
      )

    override def verify(
      m: String,
      hmac: HMACObject[String],
      k: HMACSecretKey,
      charset: Charset
    ): Boolean =
      ByteHelpers
        .fromB64String(hmac.value)
        .exists(d =>
          verify(
            m = Chunk.fromArray(
              // May throw CharacterCodingException
              m.getBytes(charset)
            ),
            HMACObject(d),
            k = k
          )
        )

    override def genKey(alg: HMACAlgorithm): Task[HMACSecretKey] = Task.effect(
      HMACSecretKey(
        KeyGenerator
          .getInstance(getAlgorithmName(alg))
          .generateKey()
      )
    )

    override def serializeKey(k: HMACSecretKey): HMACSerializedKey =
      HMACSerializedKey(
        k.underlying.getAlgorithm +
          "-" +
          ByteHelpers.toB64String(Chunk.fromArray(k.underlying.getEncoded))
      )

    override def deserializeKey(k: HMACSerializedKey): Option[HMACSecretKey] =
      k.value.split("-", 2) match {
        case Array(algorithm, b64Key) =>
          ByteHelpers
            .fromB64String(b64Key)
            .map(deserializedKey => new SecretKeySpec(deserializedKey.toArray, algorithm))
            .map(HMACSecretKey.apply)

        case _ => None
      }
  })

  /**
   * Computes the HMAC of a message `m` with the key `k`.
   *
   * @param m: the message to sign
   * @param k: the secret key to use for signing
   * @return the HMAC of `m`
   */
  def sign(m: Chunk[Byte], k: HMACSecretKey): RIO[HMAC, HMACObject[Chunk[Byte]]] =
    ZIO.access(_.get.sign(m, k))

  /**
   * Verifies that `hmac` is a valid message authentication code for `m`.
   *
   * @param m: the message to check.
   * @param hmac: the `HMAC` object to verify against.
   * @param k: the secret key used for signing.
   * @return true if `hmac` is a valid HMAC for `m` under `k`, and false otherwise.
   */
  def verify(m: Chunk[Byte], hmac: HMACObject[Chunk[Byte]], k: HMACSecretKey): RIO[HMAC, Boolean] =
    ZIO.access(_.get.verify(m, hmac, k))

  /**
   * Computes the HMAC of a message `m` with the key `k`.
   *
   * @param m: the message to sign, encoded with `charset`.
   * @param k: the secret key to use for signing.
   * @param charset: the `Charset` of `m`.
   * @return the HMAC of `m`
   */
  def sign(m: String, k: HMACSecretKey, charset: Charset): RIO[HMAC, HMACObject[String]] =
    ZIO.access(_.get.sign(m, k, charset))

  /**
   * Verifies that `hmac` is a valid message authentication code for `m`.
   *
   * @param m: the message to check.
   * @param hmac: the `HMAC` object to verify against.
   * @param k: the secret key used for signing.
   * @param charset: the `Charset` of `m`.
   * @return true if `hmac` is a valid HMAC for `m` under `k`, and false otherwise.
   */
  def verify(m: String, hmac: HMACObject[String], k: HMACSecretKey, charset: Charset): RIO[HMAC, Boolean] =
    ZIO.access(_.get.verify(m, hmac, k, charset))

  /**
   * Generates a secret key for the HMAC algorithm `alg`.
   * @param alg: The algorithm for which to generate a key.
   * @return The secret key used to sign and verify messages.
   */
  def genKey(alg: HMACAlgorithm): RIO[HMAC, HMACSecretKey] =
    ZIO.accessM(_.get.genKey(alg))

  /**
   * Serializes the HMAC secret key.
   * @param k: The key to serialize.
   * @return The serialized key.
   */
  def serializeKey(k: HMACSecretKey): RIO[HMAC, HMACSerializedKey] =
    ZIO.access(_.get.serializeKey(k))

  /**
   * Deserializes the HMAC secret key.
   * @param k: The serialized key.
   * @return The deserialized key
   */
  def deserializeKey(k: HMACSerializedKey): RIO[HMAC, Option[HMACSecretKey]] =
    ZIO.access(_.get.deserializeKey(k))

}
