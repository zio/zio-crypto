package zio.crypto.random

import zio.test.Assertion._
import zio.test._

object SecureRandomSpec extends DefaultRunnableSpec {

  def spec: Spec[Environment, TestFailure[Throwable], TestSuccess] = suite("SecureRandomSpec")(
    suite("nextString")(
      testM("Generates strings of the correct length") {
        checkM(Gen.int(0, 1000)) { x =>
          assertM(SecureRandom.nextString(x).map(_.length))(isGreaterThanEqualTo(x))
        }
      },
      testM("Fails negative length strings") {
        checkM(Gen.int(-100, -1)) { x =>
          assertM(SecureRandom.nextString(x).run)(fails(anything))
        }
      }
    ),
    suite("nextBytes")(
      testM("Generates byte arrays of the correct length") {
        checkM(Gen.int(0, 1000)) { x =>
          assertM(SecureRandom.nextBytes(x).map(_.length))(equalTo(x))
        }
      },
      testM("Fails negative length byte arrays") {
        checkM(Gen.int(-100, -1)) { x =>
          assertM(SecureRandom.nextBytes(x).run)(fails(anything))
        }
      }
    )
  ).provideCustomLayer(SecureRandom.live.orDie)
}
