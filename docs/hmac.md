---
id: hmac
title: "HMAC"
---

Hash-based message authentication codes (HMACs), are a type of 
message authentication code (MAC) that use cryptographic hash functions
and a secret key. 
They function as a kind of digital signature of
data integrity and authenticity.
HMACs use symmetric keys. The key used to sign a message is the same as is
used to verify the authenticity and integrity of the message.

## Algorithms
We support HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512.

## API
There are two basic functions provided: `sign` and `verify`.

For any message `m` and key `k`, we have that `verify(m, sign(m, k), k) == true`.

Both `sign` and `verify` are implemented in terms of 
`String` (provided you specify a `Charset`) and `Byte`.

## String Example
```scala
import java.nio.charset.StandardCharsets._

object Example extends zio.App {
  override def run(args: List[String]) = (for {
    k        <- HMAC.genKey(HMACSHA256)
    hmac     <- HMAC.sign(m, k, US_ASCII)
    verified <- HMAC.verify(m, hmac, k, US_ASCII)
  } yield verified).exitCode
    .provideLayer(HMAC.live)
}
```

## Byte Example
```scala
object Example extends zio.App {
  override def run(args: List[String]) = (for {
    m        <- SecureRandom.nextBytes(10)
    k        <- HMAC.genKey(HMACSHA256)
    hmac     <- HMAC.sign(m1, k)
    verified <- HMAC.verify(m0, hmac, k)
  } yield verified).exitCode
    .provideLayer(HMAC.live ++ SecureRandom.live.orDie)
}
```
