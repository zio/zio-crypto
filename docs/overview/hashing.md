---
id: hash
title: "Hash"
---

The `Hash` environment provides basic 1-way hash functions.

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

## Secure
If you're using `MD5` or `SHA1`, you need to explicitly not recognize that
the function you're calling is unsecure. To do so, use the function `zio.crypto.unsecure` as follows:
```scala
import sun.nio.cs.US_ASCII
import sun.security.provider.MD5
unsecure(implicit s => Hash.hash[MD5]("hello", US_ASCII))
```

## String Example
```scala
import java.nio.charset.StandardCharsets._

object Example extends zio.App {
  override def run(args: List[String]) = (for {
    digest <- Hash.hash[HashAlgorithm.SHA256](
      m = "hello",
      charset = US_ASCII
    )
    verified <- Hash.verify[HashAlgorithm.SHA256](
      m = "hello",
      digest = digest,
      charset = US_ASCII
    )
  } yield verified).exitCode
    .provideCustomLayer(Hash.live)
}
```

## Byte Example
```scala
object Example extends zio.App {
  override def run(args: List[String]) = (for {
    m <- SecureRandom.nextBytes(10)
    digest <- Hash.hash[HashAlgorithm.SHA256](
      m = m
    )
    verified <- Hash.verify[HashAlgorithm.SHA256](
      m = m,
      digest = digest
    )
  } yield verified).exitCode
    .provideCustomLayer(Hash.live ++ SecureRandom.live.orDie)
}
```
