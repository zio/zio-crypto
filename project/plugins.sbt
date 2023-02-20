val ZioSbtVersion = "0.3.10+25-abf5354a-SNAPSHOT"

addSbtPlugin("dev.zio" % "zio-sbt-ecosystem" % ZioSbtVersion)
addSbtPlugin("dev.zio" % "zio-sbt-website"   % ZioSbtVersion)
addSbtPlugin("dev.zio" % "zio-sbt-ci"        % ZioSbtVersion)

resolvers ++= Resolver.sonatypeOssRepos("public")
