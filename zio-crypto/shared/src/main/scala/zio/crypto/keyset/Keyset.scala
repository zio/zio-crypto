package zio.crypto.keyset

import com.google.crypto.tink.proto.KeyStatusType
import com.google.crypto.tink.{
  CleartextKeysetHandle,
  JsonKeysetReader,
  JsonKeysetWriter,
  KeyTemplate => TinkKeyTemplate,
  KeysetHandle => TinkKeysetHandle,
  KeysetManager => TinkKeysetManager
}
import zio.crypto.Secure
import zio.{Has, RIO, Task, ULayer, ZIO, ZLayer}

import java.nio.file.Path
import scala.annotation.implicitNotFound
import scala.jdk.CollectionConverters.ListHasAsScala

sealed trait KeyStatus
object KeyStatus {
  case object UNKNOWN      extends KeyStatus
  case object ENABLED      extends KeyStatus
  case object DISABLED     extends KeyStatus
  case object DESTROYED    extends KeyStatus
  case object UNRECOGNIZED extends KeyStatus
}
final case class KeyId(value: Int) extends AnyVal
final case class KeyInfo[Parent, Child <: Parent](id: KeyId, status: KeyStatus, url: String)

trait AsymmetricKeyset[-Family]
trait SymmetricKeyset[-Family]

class KeysetHandle[Family](
  private[crypto] val handle: TinkKeysetHandle
)(implicit val template: KeyTemplate[Family]) {
  lazy val keys: Seq[KeyInfo[Nothing, Nothing]] = handle.getKeysetInfo.getKeyInfoList.asScala.toSeq.map(x =>
    KeyInfo(
      id = KeyId(x.getKeyId),
      status = x.getStatus match {
        case KeyStatusType.UNKNOWN_STATUS => KeyStatus.UNKNOWN
        case KeyStatusType.ENABLED        => KeyStatus.ENABLED
        case KeyStatusType.DISABLED       => KeyStatus.DISABLED
        case KeyStatusType.DESTROYED      => KeyStatus.DESTROYED
        case KeyStatusType.UNRECOGNIZED   => KeyStatus.UNRECOGNIZED
      },
      url = x.getTypeUrl
    )
  )
}

final class PublicKeysetHandle[Family](private[crypto] override val handle: TinkKeysetHandle)(implicit
  override val template: KeyTemplate[Family]
) extends KeysetHandle[Family](handle)

final class PrivateKeysetHandle[Family](private[crypto] override val handle: TinkKeysetHandle)(implicit
  override val template: KeyTemplate[Family]
) extends KeysetHandle[Family](handle)

final case class PublicPrivateKeysetHandle[Family](
  publicKeyset: PublicKeysetHandle[Family],
  fullKeyset: PrivateKeysetHandle[Family]
)(implicit val template: KeyTemplate[Family])

trait KeyTemplate[Family] {
  def templateURL: String
  def getTinkKeyTemplate(algorithm: Family): TinkKeyTemplate
}

object KeysetManager {
  type KeysetManager = Has[Service]

  trait Service {
    def generateNewAsymmetric[Family, A <: Family](alg: A)(implicit
      t: KeyTemplate[Family] with AsymmetricKeyset[Family]
    ): Task[PublicPrivateKeysetHandle[Family]]
    def generateNewSymmetric[Family, A <: Family](alg: A)(implicit
      t: KeyTemplate[Family] with SymmetricKeyset[Family]
    ): Task[KeysetHandle[Family]]
    def readFromFile[Family](path: Path)(implicit
      secure: Secure[KeysetHandle[Family]],
      template: KeyTemplate[Family]
    ): Task[KeysetHandle[Family]]
    def saveToFile[Family](key: KeysetHandle[Family], path: Path)(implicit
      secure: Secure[KeysetHandle[Family]]
    ): Task[Unit]
    def add[Family, Algorithm <: Family](key: KeysetHandle[Family], alg: Algorithm): Task[KeysetHandle[Family]]
    def enable[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]]
    def disable[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]]
    def setPrimary[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]]
    def delete[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]]
    def destroy[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]]
  }

  val live: ULayer[KeysetManager] = ZLayer.succeed(new Service {
    override def saveToFile[Alg](key: KeysetHandle[Alg], path: Path)(implicit
      secure: Secure[KeysetHandle[Alg]]
    ): Task[Unit] =
      Task
        .effect(
          CleartextKeysetHandle.write(key.handle, JsonKeysetWriter.withFile(path.toFile))
        )

    override def readFromFile[Family](path: Path)(implicit
      secure: Secure[KeysetHandle[Family]],
      template: KeyTemplate[Family]
    ): Task[KeysetHandle[Family]] =
      Task.effect(new KeysetHandle(CleartextKeysetHandle.read(JsonKeysetReader.withFile(path.toFile))))

    private def copy[Family](
      key: KeysetHandle[Family],
      fn: TinkKeysetManager => TinkKeysetManager
    ): Task[KeysetHandle[Family]] =
      Task.effect {
        new KeysetHandle[Family](
          fn(TinkKeysetManager.withKeysetHandle(key.handle)).getKeysetHandle
        )(key.template)
      }

    override def add[Family, A <: Family](key: KeysetHandle[Family], algorithm: A): Task[KeysetHandle[Family]] =
      copy[Family](key, _.add(key.template.getTinkKeyTemplate(algorithm)))

    override def enable[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]] =
      copy[Family](key, _.enable(id.value))

    override def setPrimary[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]] =
      copy[Family](key, _.setPrimary(id.value))

    override def disable[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]] =
      copy[Family](key, _.disable(id.value))

    override def delete[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]] =
      copy[Family](key, _.delete(id.value))

    override def destroy[Family](key: KeysetHandle[Family], id: KeyId): Task[KeysetHandle[Family]] =
      copy[Family](key, _.destroy(id.value))

    override def generateNewSymmetric[Family, A <: Family](alg: A)(implicit
      t: KeyTemplate[Family] with SymmetricKeyset[Family]
    ): Task[KeysetHandle[Family]] =
      Task.effect(new KeysetHandle(TinkKeysetHandle.generateNew(t.getTinkKeyTemplate(alg))))

    override def generateNewAsymmetric[Family, A <: Family](alg: A)(implicit
      t: KeyTemplate[Family] with AsymmetricKeyset[Family]
    ): Task[PublicPrivateKeysetHandle[Family]] =
      Task.effect {
        val full = new KeysetHandle(TinkKeysetHandle.generateNew(t.getTinkKeyTemplate(alg)))
        PublicPrivateKeysetHandle[Family](
          publicKeyset = new PublicKeysetHandle(full.handle.getPublicKeysetHandle),
          fullKeyset = new PrivateKeysetHandle(full.handle)
        )
      }

  })

  def readFromFile[Family](path: Path)(implicit
    @implicitNotFound(
      "Reading cleartext keysets from disk is not recommended. " +
        "Prefer to encrypt your key first. " +
        "If you'd like to proceed anyhow, wrap this call as follows:\n" +
        "  unsecure(implicit s => m.readFromFile(p))"
    )
    secure: Secure[KeysetHandle[Family]],
    template: KeyTemplate[Family]
  ): RIO[KeysetManager, KeysetHandle[Family]] =
    ZIO.accessM(_.get.readFromFile(path))

  def saveToFile[Family](key: KeysetHandle[Family], path: Path)(implicit
    @implicitNotFound(
      "Storing cleartext keysets on disk is not recommended. " +
        "Prefer to encrypt your key first. " +
        "If you'd like to proceed anyhow, wrap this call as follows:\n" +
        "  unsecure(implicit s => m.saveToFile(k, p))"
    )
    secure: Secure[KeysetHandle[Family]],
    template: KeyTemplate[Family]
  ): RIO[KeysetManager, Unit] = ZIO.accessM(_.get.saveToFile(key, path))

  def generateNewSymmetric[Family, A <: Family](alg: A)(implicit
    t: KeyTemplate[Family] with SymmetricKeyset[Family]
  ): RIO[KeysetManager, KeysetHandle[Family]] =
    ZIO.accessM(_.get.generateNewSymmetric(alg))

  def generateNewAsymmetric[Family, A <: Family](alg: A)(implicit
    t: KeyTemplate[Family] with AsymmetricKeyset[Family]
  ): RIO[KeysetManager, PublicPrivateKeysetHandle[Family]] =
    ZIO.accessM(_.get.generateNewAsymmetric(alg))

  def add[Family, Algorithm <: Family](
    key: KeysetHandle[Family],
    alg: Algorithm
  ): RIO[KeysetManager, KeysetHandle[Family]] =
    ZIO.accessM(_.get.add(key, alg))

  def enable[Family](key: KeysetHandle[Family], id: KeyId): RIO[KeysetManager, KeysetHandle[Family]] =
    ZIO.accessM(_.get.enable(key, id))

  def disable[Family](key: KeysetHandle[Family], id: KeyId): RIO[KeysetManager, KeysetHandle[Family]] =
    ZIO.accessM(_.get.disable(key, id))

  def setPrimary[Family](key: KeysetHandle[Family], id: KeyId): RIO[KeysetManager, KeysetHandle[Family]] =
    ZIO.accessM(_.get.setPrimary(key, id))

  def delete[Family](key: KeysetHandle[Family], id: KeyId): RIO[KeysetManager, KeysetHandle[Family]] =
    ZIO.accessM(_.get.delete(key, id))

  def destroy[Family](key: KeysetHandle[Family], id: KeyId): RIO[KeysetManager, KeysetHandle[Family]] =
    ZIO.accessM(_.get.destroy(key, id))

}
