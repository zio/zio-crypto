[//]: # (This file was autogenerated using `zio-sbt-website` plugin via `sbt generateReadme` command.)
[//]: # (So please do not edit it manually. Instead, change "docs/index.md" file or sbt setting keys)
[//]: # (e.g. "readmeDocumentation" and "readmeSupport".)

# ZIO Crypto

Fast, secure cryptographic primitives in a ZIO & ZIO Streams friendly package. ZIO Crypto is a ZIO-idiomatic wrapper over Java's basic cryptographic functions. It provides hashing, secure random generation, and HMAC signatures and verifications.

|Project Stage | CI | Release | Snapshot | Discord | Github |
|--------------|----|---------|----------|---------|--------|
|[![Experimental](https://img.shields.io/badge/Project%20Stage-Experimental-yellowgreen.svg)](https://github.com/zio/zio/wiki/Project-Stages)        |![CI Badge](https://github.com/zio/zio-crypto/workflows/CI/badge.svg) |[![Sonatype Releases](https://img.shields.io/nexus/r/https/oss.sonatype.org/dev.zio/zio-crypto_2.12.svg)](https://oss.sonatype.org/content/repositories/releases/dev/zio/zio-crypto_2.12/) |[![Sonatype Snapshots](https://img.shields.io/nexus/s/https/oss.sonatype.org/dev.zio/zio-crypto_2.12.svg)](https://oss.sonatype.org/content/repositories/snapshots/dev/zio/zio-crypto_2.12/) |[![Chat on Discord!](https://img.shields.io/discord/629491597070827530?logo=discord)](https://discord.gg/2ccFBr4) |[![ZIO Crypto](https://img.shields.io/github/stars/zio/zio-crypto?style=social)](https://github.com/zio/zio-crypto) |

## Project Goals

### Cryptographic Implementations and Dependencies

We wish to have as few dependencies as possible this project. So, when cryptographic primitives are available via Java built-ins, we opt to use them.

However, more than not having dependencies, we do not want to offer implementations of any cryptographic primitives. So, when a new primitive is required and not available via a Java built-in, we use a package. Services using these new packages should be added under new `zio.crypto` Maven packages. 

### NIST-Recommendations and Correctness

We wish to offer the best-practice algorithms according to National Institute of Standards and Technology (NIST).

One common form of error in security is using a non-recommended algorithm with the correct interface. In an effort to keep our library easy-to-use, we try to limit the number of algorithms offered to NIST-recommended algorithms and limit less well-known and less well-used algorithms.

## Installation

```scala
libraryDependencies += "dev.zio" %% "zio-crypto" % "0.0.0+114-30324f07-SNAPSHOT"
```

## Documentation

Learn more on the [ZIO Crypto homepage](https://zio.dev/zio-crypto/)!

## Contributing

For the general guidelines, see ZIO [contributor's guide](https://zio.dev/about/contributing).

## Code of Conduct

See the [Code of Conduct](https://zio.dev/about/code-of-conduct)

## Support

Come chat with us on [![Badge-Discord]][Link-Discord].

[Badge-Discord]: https://img.shields.io/discord/629491597070827530?logo=discord "chat on discord"
[Link-Discord]: https://discord.gg/2ccFBr4 "Discord"

## License

[License](LICENSE)
