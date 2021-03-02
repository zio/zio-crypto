package zio.crypto.mac

import com.google.crypto.tink.KeysetWriter
import com.google.crypto.tink.mac.AesCmacKeyManager
import zio._
import zio.crypto.ByteHelpers
import zio.crypto.keyset.ZKeysetHandle

import java.io.{ByteArrayOutputStream, OutputStream}
import java.nio.charset.Charset
import java.security.MessageDigest
import javax.crypto.{KeyGenerator, SecretKey}
import javax.crypto.spec.SecretKeySpec
import scala.util.Try

sealed trait HMACAlgorithm

object HMACAlgorithm {
  case object HMACSHA256           extends HMACAlgorithm
  case object HMACSHA256HalfDigest extends HMACAlgorithm
  case object HMACSHA512           extends HMACAlgorithm
  case object HMACSHA512HalfDigest extends HMACAlgorithm
}

final case class HMACSerializedKey(value: String)     extends AnyVal
final case class HMACSecretKey(underlying: SecretKey) extends AnyVal
final case class HMACObject[Kind](value: Kind)        extends AnyVal

object HMAC {

  import com.google.crypto.tink.KeysetHandle
  import com.google.crypto.tink.Mac
  import com.google.crypto.tink.mac.HmacKeyManager

  HmacKeyManager.hmacSha256HalfDigestTemplate()
  HmacKeyManager.hmacSha256Template()
  HmacKeyManager.hmacSha512HalfDigestTemplate()
  HmacKeyManager.hmacSha512Template()

  // 1. Generate the key material.

  def getKeysetHandle(alg: HMACAlgorithm): KeysetHandle = KeysetHandle.generateNew(
    alg match {
      case HMACAlgorithm.HMACSHA256           => HmacKeyManager.hmacSha256Template()
      case HMACAlgorithm.HMACSHA256HalfDigest => HmacKeyManager.hmacSha256HalfDigestTemplate()
      case HMACAlgorithm.HMACSHA512           => HmacKeyManager.hmacSha512Template()
      case HMACAlgorithm.HMACSHA512HalfDigest => HmacKeyManager.hmacSha512HalfDigestTemplate()
    }
  )

  val keysetHandle: KeysetHandle = getKeysetHandle(HMACAlgorithm.HMACSHA256)

  import com.google.crypto.tink.CleartextKeysetHandle
  import com.google.crypto.tink.JsonKeysetWriter
  import java.io.File

  val keysetFilename = "my_keyset.json"
  JsonKeysetWriter.withOutputStream(ByteArrayOutputStream)
  CleartextKeysetHandle.write(
    keysetHandle,
    JsonKeysetWriter.withFile(new File(keysetFilename))
  )

  val data = new Array[Byte](20)

  // 2. Get the primitive.
  val mac = keysetHandle.getPrimitive(classOf[Mac])

  // 3. Use the primitive to compute a tag,
  val tag = mac.computeMac(data);

  // ... or to verify a tag.
  mac.verifyMac(tag, data);

  type HMAC = Has[HMAC.Service]

  trait Service {
    def sign(m: Chunk[Byte], k: HMACSecretKey): HMACObject[Chunk[Byte]]
    def verify(m: Chunk[Byte], hmac: HMACObject[Chunk[Byte]], k: HMACSecretKey): Boolean

    def sign(m: String, k: HMACSecretKey, charset: Charset): HMACObject[String]
    def verify(m: String, hmac: HMACObject[String], k: HMACSecretKey, charset: Charset): Boolean

    def genKey[Alg <: HMACAlgorithm](alg: Alg): Task[ZKeysetHandle[Alg]]
  }

  val live: ULayer[HMAC] = ZLayer.succeed(new Service {

    override def sign[A <: HMACAlgorithm](m: Chunk[Byte], k: ZKeysetHandle[A]): HMACObject[Chunk[Byte]] =
      HMACObject(
        Chunk.fromArray(
          k.keysetHandle.getPrimitive(classOf[Mac]).computeMac(m.toArray)
        )
      )

    override def verify[A <: HMACAlgorithm](
      m: Chunk[Byte],
      hmac: HMACObject[Chunk[Byte]],
      k: ZKeysetHandle[A]
    ): Boolean =
      Try(k.keysetHandle.getPrimitive(classOf[Mac]).verifyMac(hmac.value.toArray, m.toArray))
        .map(_ => true)
        .toOption
        .getOrElse(false)

    override def sign[A <: HMACAlgorithm](m: String, k: ZKeysetHandle[A], charset: Charset): HMACObject[String] =
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

    override def verify[A <: HMACAlgorithm](
      m: String,
      hmac: HMACObject[String],
      k: ZKeysetHandle[A],
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

    override def genKey[Alg <: HMACAlgorithm](alg: Alg): Task[ZKeysetHandle[Alg]] =
      Task.effect(ZKeysetHandle(getKeysetHandle(alg)))

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
