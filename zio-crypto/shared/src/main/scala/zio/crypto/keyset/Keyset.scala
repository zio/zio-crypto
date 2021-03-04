package zio.crypto.keyset

import com.google.crypto.tink.proto.KeyStatusType
import com.google.crypto.tink.{KeyTemplate => TinkKeyTemplate, KeysetHandle}

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

trait KeyTemplate[Family] {
  def getTinkKeyTemplate(algorithm: Family): TinkKeyTemplate
}

class Keyset[Family](
  private[crypto] val handle: KeysetHandle
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

trait AsymmetricKeyset[-Family]
trait SymmetricKeyset[-Family]

final class PublicKeyset[Family](private[crypto] override val handle: KeysetHandle)(implicit
  override val template: KeyTemplate[Family]
) extends Keyset(handle)

final class PrivateKeyset[Family](
  private[crypto] override val handle: KeysetHandle,
  val publicKeyset: PublicKeyset[Family]
)(implicit override val template: KeyTemplate[Family])
    extends Keyset(handle)
