package zio.crypto.random

import zio.Scope
import zio.test.Assertion._
import zio.test.{ ZIOSpecDefault, _ }

object SecureRandomSpec extends ZIOSpecDefault {

  def spec: Spec[TestEnvironment with Scope, Any] = suite("SecureRandomSpec")(
    suite("nextString")(
      test("Generates strings of the correct length") {
        check(Gen.int(0, 1000)) { x =>
          assertZIO(SecureRandom.nextString(x).map(_.length))(isGreaterThanEqualTo(x))
        }
      },
      test("Fails negative length strings") {
        check(Gen.int(-100, -1)) { x =>
          assertZIO(SecureRandom.nextString(x).exit)(fails(anything))
        }
      }
    ),
    suite("nextBytes")(
      test("Generates byte arrays of the correct length") {
        check(Gen.int(0, 1000)) { x =>
          assertZIO(SecureRandom.nextBytes(x).map(_.length))(equalTo(x))
        }
      },
      test("Fails negative length byte arrays") {
        check(Gen.int(-100, -1)) { x =>
          assertZIO(SecureRandom.nextBytes(x).exit)(fails(anything))
        }
      }
    )
  ).provideLayer(SecureRandom.live)
}
