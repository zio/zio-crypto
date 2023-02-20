val ZioSbtVersion = "0.3.10+24-f21e95cf-SNAPSHOT"

addSbtPlugin("dev.zio" % "zio-sbt-ecosystem" % ZioSbtVersion)
addSbtPlugin("dev.zio" % "zio-sbt-website"   % ZioSbtVersion)
addSbtPlugin("dev.zio" % "zio-sbt-ci"        % ZioSbtVersion)

resolvers += Resolver.sonatypeRepo("public")
