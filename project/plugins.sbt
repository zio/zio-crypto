val zioSbtVersion = "0.4.0-alpha.6+40-c57e764c-SNAPSHOT"

addSbtPlugin("dev.zio" % "zio-sbt-ecosystem" % zioSbtVersion)
addSbtPlugin("dev.zio" % "zio-sbt-website"   % zioSbtVersion)
addSbtPlugin("dev.zio" % "zio-sbt-ci"        % zioSbtVersion)

resolvers ++= Resolver.sonatypeOssRepos("public")
