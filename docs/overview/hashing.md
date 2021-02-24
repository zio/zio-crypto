---
id: hashing
title: "Hashing"
---

The `Hashing` environment provides basic 1-way hash functions.

## Algorithms
We support MD5, SHA1, SHA256, SHA384, and SHA512.

| Function | Security (in bits) against collision attacks | Dangerous?  |
|----------|----------------------------------------------|-------------|
| MD5      | <= 18 (collisions found)                     | *DANGEROUS* |
| SHA1     | < 63 (collisions found)                      | *DANGEROUS* |
| SHA256   | 128                                          |             |
| SHA384   | 192                                          |             |
| SHA512   | 256                                          |             |

## API
There are two basic functions provided: `hash` and `verify`.
For any message `m`, we have that `verify(m, hash(m)) == true`,
and for any two messages `m1`and `m2` where `m1 != m2`,
`verify(m1, hash(m2)) == false`.

Both `hash` and `verify` are implemented in terms of 
`String` (provided you specify a `Charset`) and `Byte`.

## String Example
```scala
import java.nio.charset.StandardCharsets._
import scala.util.hashing.Hashing

object Example extends zio.App {
  override def run(args: List[String]) = (for {
    digest <- Hashing.hash(
      m = "hello",
      alg = HashAlgorithm.SHA256,
      charset = US_ASCII
    )
    verified <- Hashing.verify(
      m = "hello",
      digest = digest,
      alg = HashAlgorithm.SHA256,
      charset = US_ASCII
    )
  } yield verified).exitCode
    .provideCustomLayer(Hashing.live)
}
```

## Byte Example
```scala
import scala.util.hashing.Hashing
object Example extends zio.App {
  override def run(args: List[String]) = (for {
    m <- SecureRandom.nextBytes(10)
    digest <- Hashing.hash(
      m = m,
      alg = HashAlgorithm.SHA256
    )
    verified <- Hashing.verify(
      m = m,
      digest = digest,
      alg = HashAlgorithm.SHA256
    )
  } yield verified).exitCode
    .provideCustomLayer(Hashing.live ++ SecureRandom.live.orDie)
}
```
