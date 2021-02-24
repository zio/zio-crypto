package zio.crypto.signature

import zio._
import zio.crypto.random.SecureRandom.SecureRandom

import java.security.spec.ECGenParameterSpec
import java.security.{ KeyPair, KeyPairGenerator, PrivateKey, PublicKey, Signature => JSignature }

sealed trait SignatureAlgorithm

object SignatureAlgorithm {
  case object ECDSASHA256 extends SignatureAlgorithm
  case object ECDSASHA384 extends SignatureAlgorithm
  case object ECDSASHA512 extends SignatureAlgorithm
}

object Signature {
  type Signature = Has[Signature.Service]

  trait Service {
    def genKey(alg: SignatureAlgorithm): Task[KeyPair]
    def sign(m: Array[Byte], privateKey: PrivateKey): RIO[SecureRandom, Array[Byte]]
    def verify(m: Array[Byte], signature: Array[Byte], publicKey: PublicKey): Task[Boolean]
  }

  val live: ULayer[Signature] = ZLayer.succeed(new Service {

    def genKey(alg: SignatureAlgorithm): Task[KeyPair] = Task.effect {
      val keyPairGenerator = KeyPairGenerator.getInstance("EC")
      keyPairGenerator.initialize(
        new ECGenParameterSpec(
          alg match {
            case SignatureAlgorithm.ECDSASHA256 => "P-256"
            case SignatureAlgorithm.ECDSASHA384 => "P-384"
            case SignatureAlgorithm.ECDSASHA512 => "P-521"
          }
        )
      )

//      keyPairGenerator.initialize(alg match {
//        case SignatureAlgorithm.ECDSASHA256 => 256
//        case SignatureAlgorithm.ECDSASHA384 => 384
//        case SignatureAlgorithm.ECDSASHA512 => 512
//      })
      keyPairGenerator.generateKeyPair
    }

    def getAlgorithmName(size: Int) = size match {
      case 256 => "SHA256withECDSA"
      case 384 => "SHA384withECDSA"
      case 512 => "SHA512withECDSA"
    }

    def sign(m: Array[Byte], privateKey: PrivateKey): RIO[SecureRandom, Array[Byte]] = ???
//      for {
//        random <- SecureRandom.getJavaSecureRandom
//        s <- Task.effect {
//               val signature = JSignature.getInstance(
//                 getAlgorithmName(privateKey.getAlgorithm.asInstanceOf[ECPrivateKey].getParams)
//                 privateKey.getAlgorithm
////                 "SHA256withECDSA"
//               )
//               signature.initSign(privateKey, random)
//               signature.update(m)
//               signature.sign
//             }
//      } yield s

    def verify(m: Array[Byte], signature: Array[Byte], publicKey: PublicKey): Task[Boolean] =
      Task.effect {
        val signatureBuilder = JSignature.getInstance(
          publicKey.getAlgorithm
//          "SHA256withECDSA"
        )
        signatureBuilder.initVerify(publicKey)
        signatureBuilder.update(m)
        signatureBuilder.verify(signature)
      }

  })

  def genKey(alg: SignatureAlgorithm): RIO[Signature, KeyPair] =
    ZIO.accessM(_.get.genKey(alg))

  def sign(m: Array[Byte], privateKey: PrivateKey): RIO[Signature with SecureRandom, Array[Byte]] =
    ZIO.accessM(_.get.sign(m, privateKey))

  def verify(m: Array[Byte], signature: Array[Byte], publicKey: PublicKey): RIO[Signature, Boolean] =
    ZIO.accessM(_.get.verify(m, signature, publicKey))

}
