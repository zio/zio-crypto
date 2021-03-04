package zio.crypto.mac

import com.google.crypto.tink.mac.{AesCmacKeyManager, HmacKeyManager, MacConfig}
import com.google.crypto.tink.{Mac => TinkMac, KeyTemplate => TinkKeyTemplate}
import zio._
import zio.crypto.ByteHelpers
import zio.crypto.keyset.{KeyTemplate, Keyset, SymmetricKeyset}

import java.nio.charset.Charset
import scala.util.Try

sealed trait MACAlgorithm

object MACAlgorithm {
  case object HMACSHA256           extends MACAlgorithm
  case object HMACSHA256HalfDigest extends MACAlgorithm
  case object HMACSHA512           extends MACAlgorithm
  case object HMACSHA512HalfDigest extends MACAlgorithm
  case object AES256CMAC           extends MACAlgorithm

  implicit val template: KeyTemplate[MACAlgorithm] with SymmetricKeyset[MACAlgorithm] =
    new KeyTemplate[MACAlgorithm] with SymmetricKeyset[MACAlgorithm] {
      override def getTinkKeyTemplate(a: MACAlgorithm): TinkKeyTemplate =
        a match {
          case MACAlgorithm.HMACSHA256           => HmacKeyManager.hmacSha256Template()
          case MACAlgorithm.HMACSHA256HalfDigest => HmacKeyManager.hmacSha256HalfDigestTemplate()
          case MACAlgorithm.HMACSHA512           => HmacKeyManager.hmacSha512Template()
          case MACAlgorithm.HMACSHA512HalfDigest => HmacKeyManager.hmacSha512HalfDigestTemplate()
          case MACAlgorithm.AES256CMAC           => AesCmacKeyManager.aes256CmacTemplate()
        }
    }
}

final case class MACObject[Kind](value: Kind) extends AnyVal

object MAC {

  type MAC = Has[MAC.Service]

  trait Service {
    def sign(m: Chunk[Byte], k: Keyset[MACAlgorithm]): MACObject[Chunk[Byte]]
    def verify(m: Chunk[Byte], mac: MACObject[Chunk[Byte]], k: Keyset[MACAlgorithm]): Boolean

    def sign(m: String, k: Keyset[MACAlgorithm], charset: Charset): MACObject[String]
    def verify(m: String, mac: MACObject[String], k: Keyset[MACAlgorithm], charset: Charset): Boolean
  }

  val live: TaskLayer[MAC] = Task
    .effect(MacConfig.register())
    .as {
      new Service {
        override def sign(m: Chunk[Byte], k: Keyset[MACAlgorithm]): MACObject[Chunk[Byte]] =
          MACObject(
            Chunk.fromArray(
              k.handle.getPrimitive(classOf[TinkMac]).computeMac(m.toArray)
            )
          )

        override def verify(
          m: Chunk[Byte],
          mac: MACObject[Chunk[Byte]],
          k: Keyset[MACAlgorithm]
        ): Boolean =
          Try(k.handle.getPrimitive(classOf[TinkMac]).verifyMac(mac.value.toArray, m.toArray))
            .map(_ => true)
            .toOption
            .getOrElse(false)

        override def sign(m: String, k: Keyset[MACAlgorithm], charset: Charset): MACObject[String] =
          MACObject(
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

        override def verify(m: String, mac: MACObject[String], k: Keyset[MACAlgorithm], charset: Charset): Boolean =
          ByteHelpers
            .fromB64String(mac.value)
            .exists(d =>
              verify(
                m = Chunk.fromArray(
                  // May throw CharacterCodingException
                  m.getBytes(charset)
                ),
                MACObject(d),
                k = k
              )
            )

      }
    }
    .toLayer

  /**
   * Computes the MAC of a message `m` with the key `k`.
   *
   * @param m: the message to sign
   * @param k: the secret key to use for signing
   * @return the MAC of `m`
   */
  def sign(m: Chunk[Byte], k: Keyset[MACAlgorithm]): RIO[MAC, MACObject[Chunk[Byte]]] =
    ZIO.access(_.get.sign(m, k))

  /**
   * Verifies that `mac` is a valid message authentication code for `m`.
   *
   * @param m: the message to check.
   * @param mac: the `MAC` object to verify against.
   * @param k: the secret key used for signing.
   * @return true if `mac` is a valid MAC for `m` under `k`, and false otherwise.
   */
  def verify(m: Chunk[Byte], mac: MACObject[Chunk[Byte]], k: Keyset[MACAlgorithm]): RIO[MAC, Boolean] =
    ZIO.access(_.get.verify(m, mac, k))

  /**
   * Computes the MAC of a message `m` with the key `k`.
   *
   * @param m: the message to sign, encoded with `charset`.
   * @param k: the secret key to use for signing.
   * @param charset: the `Charset` of `m`.
   * @return the MAC of `m`
   */
  def sign(m: String, k: Keyset[MACAlgorithm], charset: Charset): RIO[MAC, MACObject[String]] =
    ZIO.access(_.get.sign(m, k, charset))

  /**
   * Verifies that `mac` is a valid message authentication code for `m`.
   *
   * @param m: the message to check.
   * @param mac: the `MAC` object to verify against.
   * @param k: the secret key used for signing.
   * @param charset: the `Charset` of `m`.
   * @return true if `mac` is a valid MAC for `m` under `k`, and false otherwise.
   */
  def verify(
    m: String,
    mac: MACObject[String],
    k: Keyset[MACAlgorithm],
    charset: Charset
  ): RIO[MAC, Boolean] =
    ZIO.access(_.get.verify(m, mac, k, charset))

}
