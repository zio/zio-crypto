package zio.crypto.keyset

import com.google.crypto.tink.{
  CleartextKeysetHandle,
  JsonKeysetReader,
  JsonKeysetWriter,
  KeysetHandle => TinkKeysetHandle,
  KeysetManager => TinkKeysetManager
}
import zio.crypto.Secure
import zio.{Has, RIO, Task, ULayer, ZIO, ZLayer}

import java.nio.file.Path
import scala.annotation.implicitNotFound

object KeysetManager {
  type KeysetManager = Has[Service]

  trait Service {
    def generateNewAsymmetric[Family, A <: Family](alg: A)(implicit
      t: KeyTemplate[Family] with AsymmetricKeyset[Family]
    ): Task[PrivateKeyset[Family]]
    def generateNewSymmetric[Family, A <: Family](alg: A)(implicit
      t: KeyTemplate[Family] with SymmetricKeyset[Family]
    ): Task[Keyset[Family]]
    def readFromFile[Family](path: Path)(implicit
      secure: Secure[Keyset[Family]],
      template: KeyTemplate[Family]
    ): Task[Keyset[Family]]
    def saveToFile[Family](key: Keyset[Family], path: Path)(implicit
      secure: Secure[Keyset[Family]]
    ): Task[Unit]
    def add[Family, Algorithm <: Family](key: Keyset[Family], alg: Algorithm): Task[Keyset[Family]]
    def enable[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]]
    def disable[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]]
    def setPrimary[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]]
    def delete[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]]
    def destroy[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]]
  }

  val live: ULayer[KeysetManager] = ZLayer.succeed(new Service {
    override def saveToFile[Alg](key: Keyset[Alg], path: Path)(implicit
      secure: Secure[Keyset[Alg]]
    ): Task[Unit] =
      Task
        .effect(
          CleartextKeysetHandle.write(key.handle, JsonKeysetWriter.withFile(path.toFile))
        )

    override def readFromFile[Family](path: Path)(implicit
      secure: Secure[Keyset[Family]],
      template: KeyTemplate[Family]
    ): Task[Keyset[Family]] =
      Task.effect {
        new Keyset(CleartextKeysetHandle.read(JsonKeysetReader.withFile(path.toFile)))
      }

    private def copy[Family](
      key: Keyset[Family],
      fn: TinkKeysetManager => TinkKeysetManager
    ): Task[Keyset[Family]] =
      Task.effect {
        new Keyset[Family](
          fn(TinkKeysetManager.withKeysetHandle(key.handle)).getKeysetHandle
        )(key.template)
      }

    override def add[Family, A <: Family](key: Keyset[Family], algorithm: A): Task[Keyset[Family]] =
      copy[Family](key, _.add(key.template.getTinkKeyTemplate(algorithm)))

    override def enable[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]] =
      copy[Family](key, _.enable(id.value))

    override def setPrimary[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]] =
      copy[Family](key, _.setPrimary(id.value))

    override def disable[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]] =
      copy[Family](key, _.disable(id.value))

    override def delete[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]] =
      copy[Family](key, _.delete(id.value))

    override def destroy[Family](key: Keyset[Family], id: KeyId): Task[Keyset[Family]] =
      copy[Family](key, _.destroy(id.value))

    override def generateNewSymmetric[Family, A <: Family](alg: A)(implicit
      t: KeyTemplate[Family] with SymmetricKeyset[Family]
    ): Task[Keyset[Family]] =
      Task.effect(new Keyset(TinkKeysetHandle.generateNew(t.getTinkKeyTemplate(alg))))

    override def generateNewAsymmetric[Family, A <: Family](alg: A)(implicit
      t: KeyTemplate[Family] with AsymmetricKeyset[Family]
    ): Task[PrivateKeyset[Family]] =
      Task.effect {
        val handle = TinkKeysetHandle.generateNew(t.getTinkKeyTemplate(alg))
        new PrivateKeyset(
          handle = handle,
          publicKeyset = new PublicKeyset(handle.getPublicKeysetHandle)
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
    secure: Secure[Keyset[Family]],
    template: KeyTemplate[Family]
  ): RIO[KeysetManager, Keyset[Family]] =
    ZIO.accessM(_.get.readFromFile(path))

  def saveToFile[Family](key: Keyset[Family], path: Path)(implicit
    @implicitNotFound(
      "Storing cleartext keysets on disk is not recommended. " +
        "Prefer to encrypt your key first. " +
        "If you'd like to proceed anyhow, wrap this call as follows:\n" +
        "  unsecure(implicit s => m.saveToFile(k, p))"
    )
    secure: Secure[Keyset[Family]],
    template: KeyTemplate[Family]
  ): RIO[KeysetManager, Unit] = ZIO.accessM(_.get.saveToFile(key, path))

  def generateNewSymmetric[Family, A <: Family](alg: A)(implicit
    t: KeyTemplate[Family] with SymmetricKeyset[Family]
  ): RIO[KeysetManager, Keyset[Family]] =
    ZIO.accessM(_.get.generateNewSymmetric(alg))

  def generateNewAsymmetric[Family, A <: Family](alg: A)(implicit
    t: KeyTemplate[Family] with AsymmetricKeyset[Family]
  ): RIO[KeysetManager, PrivateKeyset[Family]] =
    ZIO.accessM(_.get.generateNewAsymmetric(alg))

  def add[Family, Algorithm <: Family](
    key: Keyset[Family],
    alg: Algorithm
  ): RIO[KeysetManager, Keyset[Family]] =
    ZIO.accessM(_.get.add(key, alg))

  def enable[Family](key: Keyset[Family], id: KeyId): RIO[KeysetManager, Keyset[Family]] =
    ZIO.accessM(_.get.enable(key, id))

  def disable[Family](key: Keyset[Family], id: KeyId): RIO[KeysetManager, Keyset[Family]] =
    ZIO.accessM(_.get.disable(key, id))

  def setPrimary[Family](key: Keyset[Family], id: KeyId): RIO[KeysetManager, Keyset[Family]] =
    ZIO.accessM(_.get.setPrimary(key, id))

  def delete[Family](key: Keyset[Family], id: KeyId): RIO[KeysetManager, Keyset[Family]] =
    ZIO.accessM(_.get.delete(key, id))

  def destroy[Family](key: Keyset[Family], id: KeyId): RIO[KeysetManager, Keyset[Family]] =
    ZIO.accessM(_.get.destroy(key, id))

}
