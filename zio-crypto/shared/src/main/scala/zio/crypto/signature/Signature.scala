package zio.crypto.signature

import zio._
import zio.crypto.random.SecureRandom
import zio.crypto.random.SecureRandom.SecureRandom

import java.security.{KeyPairGenerator, PrivateKey, PublicKey, Signature => JSignature}

case class SignatureObject(value: Chunk[Byte]) extends AnyVal
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
    def sign(m: Chunk[Byte], privateKey: SignaturePrivateKey): RIO[SecureRandom, SignatureObject]
    def verify(m: Chunk[Byte], signature: SignatureObject, publicKey: SignaturePublicKey): Task[Boolean]
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

    def sign(m: Chunk[Byte], privateKey: SignaturePrivateKey): RIO[SecureRandom, SignatureObject] =
      SecureRandom.execute { random =>
        val signature = JSignature.getInstance(getAlgorithmName(privateKey.algorithm))
        signature.initSign(privateKey.key, random)
        signature.update(m.toArray)
        signature.sign
      }
        .map(s => SignatureObject(Chunk.fromArray(s)))

    def verify(m: Chunk[Byte], signature: SignatureObject, publicKey: SignaturePublicKey): Task[Boolean] =
      Task.effect {
        val signatureBuilder = JSignature.getInstance(getAlgorithmName(publicKey.algorithm))
        signatureBuilder.initVerify(publicKey.key)
        signatureBuilder.update(m.toArray)
        signatureBuilder.verify(signature.value.toArray)
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
  def sign(m: Chunk[Byte], privateKey: SignaturePrivateKey): RIO[Signature with SecureRandom, SignatureObject] =
    ZIO.accessM(_.get.sign(m, privateKey))

  /**
   * Verifies that the signature `signature` is a valid signature for `m`.
   *
   * @param m: The message to use in verification.
   * @param signature: The signature to verify.
   * @param publicKey: The public key that should be used to check verification.
   * @return True if verified and false otherwise.
   */
  def verify(m: Chunk[Byte], signature: SignatureObject, publicKey: SignaturePublicKey): RIO[Signature, Boolean] =
    ZIO.accessM(_.get.verify(m, signature, publicKey))

}
