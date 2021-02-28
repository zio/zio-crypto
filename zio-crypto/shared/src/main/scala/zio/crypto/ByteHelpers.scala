package zio.crypto

import zio.{ Chunk, Task }

import java.util.Base64

private[crypto] object ByteHelpers {
  def toB64String(decoded: Chunk[Byte]): String = Base64.getEncoder.encodeToString(decoded.toArray)

  def fromB64String(encoded: String): Task[Chunk[Byte]] = Task
    .effect(Base64.getDecoder.decode(encoded))
    .map(Chunk.fromArray)
}
