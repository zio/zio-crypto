package zio.crypto.signature

import com.google.crypto.tink.signature.{EcdsaSignKeyManager, SignatureConfig}
import com.google.crypto.tink.{PublicKeySign, PublicKeyVerify, KeyTemplate => TinkKeyTemplate}
import zio._
import zio.crypto.ByteHelpers
import zio.crypto.keyset.{AsymmetricKeyset, KeyTemplate, PrivateKeysetHandle, PublicKeysetHandle}

import java.nio.charset.Charset
import scala.util.Try

case class SignatureObject[T](value: T) extends AnyVal
sealed trait SignatureAlgorithm

object SignatureAlgorithm {
  case object ECDSAP256 extends SignatureAlgorithm

  implicit val template: KeyTemplate[SignatureAlgorithm] with AsymmetricKeyset[SignatureAlgorithm] =
    new KeyTemplate[SignatureAlgorithm] with AsymmetricKeyset[SignatureAlgorithm] {
      override def templateURL: String = "type.googleapis.com/google.crypto.tink.Signature???"

      override def getTinkKeyTemplate(a: SignatureAlgorithm): TinkKeyTemplate =
        a match {
          case ECDSAP256 => EcdsaSignKeyManager.ecdsaP256Template()
        }
    }
}

object Signature {
  type Signature = Has[Signature.Service]

  trait Service {
    def sign(
      m: Chunk[Byte],
      privateKey: PrivateKeysetHandle[SignatureAlgorithm]
    ): Task[SignatureObject[Chunk[Byte]]]
    def sign(
      m: String,
      privateKey: PrivateKeysetHandle[SignatureAlgorithm],
      charset: Charset
    ): Task[SignatureObject[String]]
    def verify(
      m: Chunk[Byte],
      signature: SignatureObject[Chunk[Byte]],
      publicKey: PublicKeysetHandle[SignatureAlgorithm]
    ): Task[Boolean]
    def verify(
      m: String,
      signature: SignatureObject[String],
      publicKey: PublicKeysetHandle[SignatureAlgorithm],
      charset: Charset
    ): Task[Boolean]
  }

  val live: TaskLayer[Signature] = Task
    .effect(SignatureConfig.register())
    .as(new Service {
      def sign(
        m: Chunk[Byte],
        privateKey: PrivateKeysetHandle[SignatureAlgorithm]
      ): Task[SignatureObject[Chunk[Byte]]] =
        Task.effect(
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
        publicKey: PublicKeysetHandle[SignatureAlgorithm]
      ): Task[Boolean] =
        Task.effect {
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
        privateKey: PrivateKeysetHandle[SignatureAlgorithm],
        charset: Charset
      ): Task[SignatureObject[String]] =
        sign(Chunk.fromArray(m.getBytes(charset)), privateKey)
          .map(x => SignatureObject(ByteHelpers.toB64String(x.value)))

      override def verify(
        m: String,
        signature: SignatureObject[String],
        publicKey: PublicKeysetHandle[SignatureAlgorithm],
        charset: Charset
      ): Task[Boolean] =
        ByteHelpers.fromB64String(signature.value) match {
          case Some(signatureBytes) =>
            verify(
              m = Chunk.fromArray(m.getBytes(charset)),
              signature = SignatureObject(signatureBytes),
              publicKey = publicKey
            )
          case _ => UIO(false)
        }
    })
    .toLayer

  /**
   * Signs a message `m` with the private key `privateKey`.
   *
   * @param m: The message to sign.
   * @param privateKey: The private key to use in signing.
   * @return The signature.
   */
  def sign(
    m: Chunk[Byte],
    privateKey: PrivateKeysetHandle[SignatureAlgorithm]
  ): RIO[Signature, SignatureObject[Chunk[Byte]]] =
    ZIO.accessM(_.get.sign(m, privateKey))

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
    privateKey: PrivateKeysetHandle[SignatureAlgorithm],
    charset: Charset
  ): RIO[Signature, SignatureObject[String]] =
    ZIO.accessM(_.get.sign(m, privateKey, charset))

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
    publicKey: PublicKeysetHandle[SignatureAlgorithm]
  ): RIO[Signature, Boolean] =
    ZIO.accessM(_.get.verify(m, signature, publicKey))

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
    publicKey: PublicKeysetHandle[SignatureAlgorithm],
    charset: Charset
  ): RIO[Signature, Boolean] =
    ZIO.accessM(_.get.verify(m, signature, publicKey, charset))

}
