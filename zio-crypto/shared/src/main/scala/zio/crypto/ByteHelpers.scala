package zio.crypto

import zio.Task

import java.util.Base64

private[crypto] object ByteHelpers {
  def toB64String(decoded: Array[Byte]): String         = Base64.getEncoder.encodeToString(decoded)
  def toB64String(decoded: Seq[Byte]): String           = Base64.getEncoder.encodeToString(decoded.toArray)
  def fromB64String(encoded: String): Task[Array[Byte]] = Task.effect(Base64.getDecoder.decode(encoded))
}
