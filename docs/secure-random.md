---
id: secure-random
title: "Secure Random"
---

The implementation wraps `java.crypto.SecureRandom` with `ZIO` bindings.
We choose the system-default security Provider.

`SecureRandom` generates random bytes, and random base64-encoded strings.

## Random Strings
Strings generated from `SecureRandom` are base-64 encoded.
This encoding means that generated strings are longer than 
the supplied `entropyBytes`.

```scala
import zio.crypto.random.SecureRandom
SecureRandom.nextString(entropyBytes = 8)
```

## Random Bytes
```scala
import zio.crypto.random.SecureRandom
SecureRandom.nextBytes(5)
```

## Runnable Example
```scala
import zio.crypto.random.SecureRandom

object Example extends zio.App {
    override def run(args: List[String]) = (for {
        randBytes <- SecureRandom.nextBytes(5)
        randString <- SecureRandom.nextString(5)
    } yield ExitCode.success)
      .provideCustomLayer(SecureRandom.live.orDie)
    
}
```
