package zio.crypto.signature

import java.nio.charset.Charset
import java.security.{ KeyPairGenerator, PrivateKey, PublicKey, Signature => JSignature }

import zio._
import zio.crypto.ByteHelpers
import zio.crypto.random.SecureRandom
import zio.crypto.random.SecureRandom.SecureRandom

case class SignatureObject[T](value: T) extends AnyVal
sealed trait SignatureAlgorithm

object SignatureAlgorithm {
  case object ECDSASHA256 extends SignatureAlgorithm
  case object ECDSASHA384 extends SignatureAlgorithm
  case object ECDSASHA512 extends SignatureAlgorithm
}

case class SignaturePrivateKey(key: PrivateKey, algorithm: SignatureAlgorithm)
case class SignaturePublicKey(key: PublicKey, algorithm: SignatureAlgorithm)
case class SignatureKeyPair(publicKey: SignaturePublicKey, privateKey: SignaturePrivateKey)

object Signature {
  type Signature = Has[Signature.Service]

  trait Service {
    def genKey(alg: SignatureAlgorithm): Task[SignatureKeyPair]
    def sign(m: Chunk[Byte], privateKey: SignaturePrivateKey): RIO[SecureRandom, SignatureObject[Chunk[Byte]]]
    def sign(m: String, privateKey: SignaturePrivateKey, charset: Charset): RIO[SecureRandom, SignatureObject[String]]
    def verify(m: Chunk[Byte], signature: SignatureObject[Chunk[Byte]], publicKey: SignaturePublicKey): Task[Boolean]
    def verify(
      m: String,
      signature: SignatureObject[String],
      publicKey: SignaturePublicKey,
      charset: Charset
    ): Task[Boolean]
  }

  val live: ULayer[Signature] = ZLayer.succeed(new Service {

    private def getAlgorithmName(alg: SignatureAlgorithm) = alg match {
      case SignatureAlgorithm.ECDSASHA256 => "SHA256withECDSA"
      case SignatureAlgorithm.ECDSASHA384 => "SHA384withECDSA"
      case SignatureAlgorithm.ECDSASHA512 => "SHA512withECDSA"
    }

    def genKey(alg: SignatureAlgorithm): Task[SignatureKeyPair] = Task.effect {
      val keyPairGenerator = KeyPairGenerator.getInstance("EC")
      val keypair          = keyPairGenerator.generateKeyPair
      SignatureKeyPair(
        publicKey = SignaturePublicKey(keypair.getPublic, alg),
        privateKey = SignaturePrivateKey(keypair.getPrivate, alg)
      )
    }

    def sign(m: Chunk[Byte], privateKey: SignaturePrivateKey): RIO[SecureRandom, SignatureObject[Chunk[Byte]]] =
      SecureRandom.execute { random =>
        val signature = JSignature.getInstance(getAlgorithmName(privateKey.algorithm))
        signature.initSign(privateKey.key, random)
        signature.update(m.toArray)
        signature.sign
      }
        .map(s => SignatureObject(Chunk.fromArray(s)))

    def verify(m: Chunk[Byte], signature: SignatureObject[Chunk[Byte]], publicKey: SignaturePublicKey): Task[Boolean] =
      Task.effect {
        val signatureBuilder = JSignature.getInstance(getAlgorithmName(publicKey.algorithm))
        signatureBuilder.initVerify(publicKey.key)
        signatureBuilder.update(m.toArray)
        signatureBuilder.verify(signature.value.toArray)
      }

    override def sign(
      m: String,
      privateKey: SignaturePrivateKey,
      charset: Charset
    ): RIO[SecureRandom, SignatureObject[String]] =
      sign(Chunk.fromArray(m.getBytes(charset)), privateKey)
        .map(x => SignatureObject(ByteHelpers.toB64String(x.value)))

    override def verify(
      m: String,
      signature: SignatureObject[String],
      publicKey: SignaturePublicKey,
      charset: Charset
    ): Task[Boolean] =
      ByteHelpers.fromB64String(signature.value) match {
        case Some(signatureBytes) =>
          verify(
            m = Chunk.fromArray(m.getBytes(charset)),
            signature = SignatureObject(signatureBytes),
            publicKey = publicKey
          )
        case _                    => UIO(false)
      }
  })

  /**
   * Generates a keypair to use for signing and verifying messages.
   *
   * @param alg: The algorithm for which to generate keys.
   * @return the keypair
   */
  def genKey(alg: SignatureAlgorithm): RIO[Signature, SignatureKeyPair] =
    ZIO.accessM(_.get.genKey(alg))

  /**
   * Signs a message `m` with the private key `privateKey`.
   *
   * @param m: The message to sign.
   * @param privateKey: The private key to use in signing.
   * @return The signature.
   */
  def sign(
    m: Chunk[Byte],
    privateKey: SignaturePrivateKey
  ): RIO[Signature with SecureRandom, SignatureObject[Chunk[Byte]]] =
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
    privateKey: SignaturePrivateKey,
    charset: Charset
  ): RIO[Signature with SecureRandom, SignatureObject[String]] =
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
    publicKey: SignaturePublicKey
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
    publicKey: SignaturePublicKey,
    charset: Charset
  ): RIO[Signature, Boolean] =
    ZIO.accessM(_.get.verify(m, signature, publicKey, charset))

}
