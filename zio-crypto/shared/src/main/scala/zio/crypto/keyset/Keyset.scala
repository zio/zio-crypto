package zio.crypto.keyset

import com.google.crypto.tink.{
  CleartextKeysetHandle,
  JsonKeysetReader,
  JsonKeysetWriter,
  KeyTemplate,
  KeysetHandle,
  KeysetManager => TinkKeysetManager
}
import zio.{Has, RIO, Task, ULayer, ZIO, ZLayer}
import zio.crypto.Secure

import java.nio.file.Path
import scala.annotation.implicitNotFound

case class ZKeysetHandle[Alg](keysetHandle: KeysetHandle)

object KeysetManager {
  type KeysetManager = Has[Service]

  trait Service {
    def readFromFile[Alg](path: Path)(implicit secure: Secure[ZKeysetHandle[Alg]]): Task[ZKeysetHandle[Alg]]
    def saveToFile[Alg](key: ZKeysetHandle[Alg], path: Path)(implicit secure: Secure[ZKeysetHandle[Alg]]): Task[Unit]
    def rotate[Alg](key: ZKeysetHandle[Alg]): Task[ZKeysetHandle[Alg]]
  }

  val live: ULayer[KeysetManager] = ZLayer.succeed(new Service {
    override def saveToFile[Alg](key: ZKeysetHandle[Alg], path: Path)(implicit
      secure: Secure[ZKeysetHandle[Alg]]
    ): Task[Unit] =
      Task
        .effect(
          CleartextKeysetHandle.write(key.keysetHandle, JsonKeysetWriter.withFile(path.toFile))
        )

    override def readFromFile[Alg](path: Path)(implicit secure: Secure[ZKeysetHandle[Alg]]): Task[ZKeysetHandle[Alg]] =
      Task.effect(ZKeysetHandle(CleartextKeysetHandle.read(JsonKeysetReader.withFile(path.toFile))))

    private def modify[Alg](key: ZKeysetHandle[Alg], fn: TinkKeysetManager => TinkKeysetManager) =
      Task.effect {
        ZKeysetHandle[Alg](
          fn(TinkKeysetManager.withKeysetHandle(key.keysetHandle)).getKeysetHandle
        )
      }

    override def add[Alg](key: ZKeysetHandle[Alg], template: KeyTemplate): Task[ZKeysetHandle[Alg]] =
      modify[Alg](key, _.add(template))

    override def enable[Alg](key: ZKeysetHandle[Alg], id: Int): Task[ZKeysetHandle[Alg]] =
      modify[Alg](key, _.enable(id))

    override def setPrimary[Alg](key: ZKeysetHandle[Alg], id: Int): Task[ZKeysetHandle[Alg]] =
      modify[Alg](key, _.setPrimary(id))

    override def disable[Alg](key: ZKeysetHandle[Alg], id: Int): Task[ZKeysetHandle[Alg]] =
      modify[Alg](key, _.disable(id))

    override def delete[Alg](key: ZKeysetHandle[Alg], id: Int): Task[ZKeysetHandle[Alg]] =
      modify[Alg](key, _.delete(id))

    override def destroy[Alg](key: ZKeysetHandle[Alg], id: Int): Task[ZKeysetHandle[Alg]] =
      modify[Alg](key, _.destroy(id))

  })

  def readFromFile[Alg](path: Path)(implicit
    @implicitNotFound(
      "Reading cleartext keysets from disk is not recommended. " +
        "Prefer to encrypt your key first. " +
        "If you'd like to proceed anyhow, wrap this call as follows:\n" +
        "  unsecure(implicit s => m.readFromFile(p))"
    )
    secure: Secure[ZKeysetHandle[Alg]]
  ): RIO[KeysetManager, ZKeysetHandle[Alg]] =
    ZIO.accessM(_.get.readFromFile(path))

  def saveToFile[Alg](key: ZKeysetHandle[Alg], path: Path)(implicit
    @implicitNotFound(
      "Storing cleartext keysets on disk is not recommended. " +
        "Prefer to encrypt your key first. " +
        "If you'd like to proceed anyhow, wrap this call as follows:\n" +
        "  unsecure(implicit s => m.saveToFile(k, p))"
    )
    secure: Secure[ZKeysetHandle[Alg]]
  ): RIO[KeysetManager, Unit] = ZIO.accessM(_.get.saveToFile(key, path))

}
