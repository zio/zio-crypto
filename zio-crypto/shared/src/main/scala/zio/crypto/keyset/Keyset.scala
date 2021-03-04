package zio.crypto.keyset

import com.google.crypto.tink.proto.KeyStatusType
import com.google.crypto.tink.{
  CleartextKeysetHandle,
  JsonKeysetReader,
  JsonKeysetWriter,
  KeysetHandle => TinkKeysetHandle,
  KeysetManager => TinkKeysetManager
}
import zio.crypto.Secure
import zio.{Has, RIO, Task, ULayer, ZIO, ZLayer}
import com.google.crypto.tink.{KeyTemplate => TinkKeyTemplate}

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

class ZKeysetHandle[Family](handle: TinkKeysetHandle)(implicit val template: KeyTemplate[Family]) {
  private[crypto] def keysetHandle = handle

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

trait KeyTemplate[Family] {
  def templateURL: String
  def getTinkKeyTemplate(algorithm: Family): TinkKeyTemplate
}

object KeysetManager {
  type KeysetManager = Has[Service]

  trait Service {
    def generateNew[Family, A <: Family](alg: A)(implicit t: KeyTemplate[Family]): Task[ZKeysetHandle[Family]]
    def readFromFile[Family](path: Path)(implicit
      secure: Secure[ZKeysetHandle[Family]],
      template: KeyTemplate[Family]
    ): Task[ZKeysetHandle[Family]]
    def saveToFile[Family](key: ZKeysetHandle[Family], path: Path)(implicit
      secure: Secure[ZKeysetHandle[Family]]
    ): Task[Unit]
    def add[Family, Algorithm <: Family](key: ZKeysetHandle[Family], alg: Algorithm): Task[ZKeysetHandle[Family]]
    def enable[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]]
    def disable[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]]
    def setPrimary[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]]
    def delete[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]]
    def destroy[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]]
  }

  val live: ULayer[KeysetManager] = ZLayer.succeed(new Service {
    override def saveToFile[Alg](key: ZKeysetHandle[Alg], path: Path)(implicit
      secure: Secure[ZKeysetHandle[Alg]]
    ): Task[Unit] =
      Task
        .effect(
          CleartextKeysetHandle.write(key.keysetHandle, JsonKeysetWriter.withFile(path.toFile))
        )

    override def readFromFile[Family](path: Path)(implicit
      secure: Secure[ZKeysetHandle[Family]],
      template: KeyTemplate[Family]
    ): Task[ZKeysetHandle[Family]] =
      Task.effect(new ZKeysetHandle(CleartextKeysetHandle.read(JsonKeysetReader.withFile(path.toFile))))

    private def copy[Family](
      key: ZKeysetHandle[Family],
      fn: TinkKeysetManager => TinkKeysetManager
    ): Task[ZKeysetHandle[Family]] =
      Task.effect {
        new ZKeysetHandle[Family](
          fn(TinkKeysetManager.withKeysetHandle(key.keysetHandle)).getKeysetHandle
        )(key.template)
      }

    override def add[Family, A <: Family](key: ZKeysetHandle[Family], algorithm: A): Task[ZKeysetHandle[Family]] =
      copy[Family](key, _.add(key.template.getTinkKeyTemplate(algorithm)))

    override def enable[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]] =
      copy[Family](key, _.enable(id.value))

    override def setPrimary[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]] =
      copy[Family](key, _.setPrimary(id.value))

    override def disable[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]] =
      copy[Family](key, _.disable(id.value))

    override def delete[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]] =
      copy[Family](key, _.delete(id.value))

    override def destroy[Family](key: ZKeysetHandle[Family], id: KeyId): Task[ZKeysetHandle[Family]] =
      copy[Family](key, _.destroy(id.value))

    override def generateNew[Family, A <: Family](alg: A)(implicit
      template: KeyTemplate[Family]
    ): Task[ZKeysetHandle[Family]] =
      Task.effect(new ZKeysetHandle(TinkKeysetHandle.generateNew(template.getTinkKeyTemplate(alg))))

  })

  def readFromFile[Family](path: Path)(implicit
    @implicitNotFound(
      "Reading cleartext keysets from disk is not recommended. " +
        "Prefer to encrypt your key first. " +
        "If you'd like to proceed anyhow, wrap this call as follows:\n" +
        "  unsecure(implicit s => m.readFromFile(p))"
    )
    secure: Secure[ZKeysetHandle[Family]],
    template: KeyTemplate[Family]
  ): RIO[KeysetManager, ZKeysetHandle[Family]] =
    ZIO.accessM(_.get.readFromFile(path))

  def saveToFile[Family](key: ZKeysetHandle[Family], path: Path)(implicit
    @implicitNotFound(
      "Storing cleartext keysets on disk is not recommended. " +
        "Prefer to encrypt your key first. " +
        "If you'd like to proceed anyhow, wrap this call as follows:\n" +
        "  unsecure(implicit s => m.saveToFile(k, p))"
    )
    secure: Secure[ZKeysetHandle[Family]],
    template: KeyTemplate[Family]
  ): RIO[KeysetManager, Unit] = ZIO.accessM(_.get.saveToFile(key, path))

  def generateNew[Family, A <: Family](alg: A)(implicit
    t: KeyTemplate[Family]
  ): RIO[KeysetManager, ZKeysetHandle[Family]] =
    ZIO.accessM(_.get.generateNew(alg))

  def add[Family, Algorithm <: Family](
    key: ZKeysetHandle[Family],
    alg: Algorithm
  ): RIO[KeysetManager, ZKeysetHandle[Family]] =
    ZIO.accessM(_.get.add(key, alg))

  def enable[Family](key: ZKeysetHandle[Family], id: KeyId): RIO[KeysetManager, ZKeysetHandle[Family]] =
    ZIO.accessM(_.get.enable(key, id))

  def disable[Family](key: ZKeysetHandle[Family], id: KeyId): RIO[KeysetManager, ZKeysetHandle[Family]] =
    ZIO.accessM(_.get.disable(key, id))

  def setPrimary[Family](key: ZKeysetHandle[Family], id: KeyId): RIO[KeysetManager, ZKeysetHandle[Family]] =
    ZIO.accessM(_.get.setPrimary(key, id))

  def delete[Family](key: ZKeysetHandle[Family], id: KeyId): RIO[KeysetManager, ZKeysetHandle[Family]] =
    ZIO.accessM(_.get.delete(key, id))

  def destroy[Family](key: ZKeysetHandle[Family], id: KeyId): RIO[KeysetManager, ZKeysetHandle[Family]] =
    ZIO.accessM(_.get.destroy(key, id))

}
