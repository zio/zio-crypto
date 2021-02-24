---
id: about_index
title:  "About zio-crypto"
---

## Project Goals

### Cryptographic Implementations and Dependencies

We wish to have as few dependencies as possible this project. 
So, when cryptographic primitives are available via Java
built-ins, we opt to use them.

However, more than not having dependencies,
we do not want to offer implementations of any 
cryptographic primitives.
So, when a new primitive is required and not
available via a Java built-in, we use a package.
Services using these new packages should be added
under new `zio.crypto` Maven packages.


### NIST-Recommendations and Correctness

We wish to offer the best-practice algorithms according to
National Institute of Standards and Technology (NIST).

One common form of error in security is using 
a non-recommended algorithm with the correct interface.
In an effort to keep our library easy-to-use,
we try to limit the number of algorithms
offered to NIST-recommended algorithms and limit
less well-known and less well-used algorithms.


