package zio.crypto.signature

import java.nio.charset.Charset

import scala.util.Try

import com.google.crypto.tink.signature.SignatureConfig
import com.google.crypto.tink.{ KeyTemplate => TinkKeyTemplate, KeyTemplates, PublicKeySign, PublicKeyVerify }

import zio._
import zio.crypto.ByteHelpers
import zio.crypto.keyset.{ AsymmetricKeyset, KeyTemplate, PrivateKeyset, PublicKeyset }

case class SignatureObject[T](value: T) extends AnyVal
sealed trait SignatureAlgorithm

object SignatureAlgorithm {

  case object ECDSA_P256              extends SignatureAlgorithm
  case object ED25519                 extends SignatureAlgorithm
  case object Rsa3072SsaPkcs1Sha256F4 extends SignatureAlgorithm

  implicit val template: KeyTemplate[SignatureAlgorithm] with AsymmetricKeyset[SignatureAlgorithm] =
    new KeyTemplate[SignatureAlgorithm] with AsymmetricKeyset[SignatureAlgorithm] {
      override def getTinkKeyTemplate(a: SignatureAlgorithm): TinkKeyTemplate =
        a match {
          case SignatureAlgorithm.ECDSA_P256              =>
            KeyTemplates.get("ECDSA_P256")
          case SignatureAlgorithm.ED25519                 =>
            KeyTemplates.get("ED25519")
          case SignatureAlgorithm.Rsa3072SsaPkcs1Sha256F4 =>
            KeyTemplates.get("RSA_SSA_PKCS1_3072_SHA256_F4")
        }
    }
}

trait Signature {
  def sign(
    m: Chunk[Byte],
    privateKey: PrivateKeyset[SignatureAlgorithm]
  ): Task[SignatureObject[Chunk[Byte]]]
  def sign(
    m: String,
    privateKey: PrivateKeyset[SignatureAlgorithm],
    charset: Charset
  ): Task[SignatureObject[String]]
  def verify(
    m: Chunk[Byte],
    signature: SignatureObject[Chunk[Byte]],
    publicKey: PublicKeyset[SignatureAlgorithm]
  ): Task[Boolean]
  def verify(
    m: String,
    signature: SignatureObject[String],
    publicKey: PublicKeyset[SignatureAlgorithm],
    charset: Charset
  ): Task[Boolean]
}

private object SignatureLive extends Signature {
  def sign(
    m: Chunk[Byte],
    privateKey: PrivateKeyset[SignatureAlgorithm]
  ): Task[SignatureObject[Chunk[Byte]]] =
    ZIO.attempt(
      SignatureObject(
        Chunk.fromArray(
          privateKey.handle
            .getPrimitive(classOf[PublicKeySign])
            .sign(m.toArray)
        )
      )
    )

  def verify(
    m: Chunk[Byte],
    signature: SignatureObject[Chunk[Byte]],
    publicKey: PublicKeyset[SignatureAlgorithm]
  ): Task[Boolean] =
    ZIO.attempt {
      Try(
        publicKey.handle
          .getPrimitive(classOf[PublicKeyVerify])
          .verify(
            signature.value.toArray,
            m.toArray
          )
      ).toOption.isDefined
    }

  override def sign(
    m: String,
    privateKey: PrivateKeyset[SignatureAlgorithm],
    charset: Charset
  ): Task[SignatureObject[String]] =
    sign(Chunk.fromArray(m.getBytes(charset)), privateKey)
      .map(x => SignatureObject(ByteHelpers.toB64String(x.value)))

  override def verify(
    m: String,
    signature: SignatureObject[String],
    publicKey: PublicKeyset[SignatureAlgorithm],
    charset: Charset
  ): Task[Boolean] =
    ByteHelpers.fromB64String(signature.value) match {
      case Some(signatureBytes) =>
        verify(
          m = Chunk.fromArray(m.getBytes(charset)),
          signature = SignatureObject(signatureBytes),
          publicKey = publicKey
        )
      case _                    => ZIO.succeed(false)
    }
}

object Signature {

  val live: TaskLayer[Signature] = ZLayer {
    ZIO
      .attempt(SignatureConfig.register())
      .as(SignatureLive)
  }

  /**
   * Signs a message `m` with the private key `privateKey`.
   *
   * @param m: The message to sign.
   * @param privateKey: The private key to use in signing.
   * @return The signature.
   */
  def sign(
    m: Chunk[Byte],
    privateKey: PrivateKeyset[SignatureAlgorithm]
  ): RIO[Signature, SignatureObject[Chunk[Byte]]] =
    ZIO.serviceWithZIO(_.sign(m, privateKey))

  /**
   * Signs a message `m` with the private key `privateKey`.
   *
   * @param m: The message to sign.
   * @param privateKey: The private key to use in signing.
   * @param charset: The charset of `m`.
   * @return The signature.
   */
  def sign(
    m: String,
    privateKey: PrivateKeyset[SignatureAlgorithm],
    charset: Charset
  ): RIO[Signature, SignatureObject[String]] =
    ZIO.serviceWithZIO(_.sign(m, privateKey, charset))

  /**
   * Verifies that the signature `signature` is a valid signature for `m`.
   *
   * @param m: The message to use in verification.
   * @param signature: The signature to verify.
   * @param publicKey: The public key that should be used to check verification.
   * @return True if verified and false otherwise.
   */
  def verify(
    m: Chunk[Byte],
    signature: SignatureObject[Chunk[Byte]],
    publicKey: PublicKeyset[SignatureAlgorithm]
  ): RIO[Signature, Boolean] =
    ZIO.serviceWithZIO(_.verify(m, signature, publicKey))

  /**
   * Verifies that the signature `signature` is a valid signature for `m`.
   *
   * @param m: The message to use in verification.
   * @param signature: The signature to verify.
   * @param publicKey: The public key that should be used to check verification.
   * @param charset: The charset used to encode `m`.
   * @return True if verified and false otherwise.
   */
  def verify(
    m: String,
    signature: SignatureObject[String],
    publicKey: PublicKeyset[SignatureAlgorithm],
    charset: Charset
  ): RIO[Signature, Boolean] =
    ZIO.serviceWithZIO(_.verify(m, signature, publicKey, charset))

}
