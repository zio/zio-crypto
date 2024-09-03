---
id: hash
title: "Hash"
---

The `Hash` environment provides basic 1-way hash functions.

## Algorithms
We support MD5, SHA1, SHA256, SHA384, and SHA512.

| Function | Security (in bits) against collision attacks | Dangerous?  |
| -------- | -------------------------------------------- | ----------- |
| MD5      | \<= 18 (collisions found)                    | _DANGEROUS_ |
| SHA1     | < 63 (collisions found)                      | _DANGEROUS_ |
| SHA256   | 128                                          |             |
| SHA384   | 192                                          |             |
| SHA512   | 256                                          |             |

## API
There are two basic functions provided: `hash` and `verify`.
For any message `m`, we have that `verify(m, hash(m)) == true`,
and for any two messages `m1`and `m2` where `m1 != m2`,
`verify(m1, hash(m2)) == false`.

Both `hash` and `verify` are implemented in terms of 
`String` (provided you specify a `Charset`) and `Chunk[Byte]`.

## Usage
To use the hashing service, simply call the method hash
with a type parameter specifying the algorithm you wish
to use.
```scala
import java.nio.charset.StandardCharsets.US_ASCII
import zio.crypto.hash.{Hash, HashAlgorithm}
Hash.hash[HashAlgorithm.SHA256]("hello", US_ASCII)
```

However, we need to take special case when using algorithms
marked *DANGEROUS* in the table above.

### Secure
If you're using `MD5` or `SHA1`, you need to explicitly not recognize that
the function you're calling is unsecure. To do so, use the function `zio.crypto.unsecure` as follows:
```scala
import zio.crypto.unsecure
unsecure(implicit s => Hash.hash[HashAlgorithm.MD5]("hello", US_ASCII))
```

## String Example
```scala
import java.nio.charset.StandardCharsets.US_ASCII
import zio.crypto.hash.{Hash, HashAlgorithm}

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
import zio.crypto.hash.{Hash, HashAlgorithm}
import zio.crypto.random.SecureRandom

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
