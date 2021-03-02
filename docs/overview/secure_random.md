---
id: secure_random
title: "Secure Random"
---

The implementation wraps `java.crypto.SecureRandom` with `ZIO` bindings.
We choose the system-default security Provider.

`SecureRandom` generates random bytes, and random base64-encoded strings.

## Random Strings
Strings generated from `SecureRandom` are base-64 encoded.
Note that strings generated will be longer than the supplied number
of characters, and that instead the caller specifies the number
of bytes of entropy to include in the string.

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
      .provideCustomLayer(SecureRandom.live)
    
}
```
