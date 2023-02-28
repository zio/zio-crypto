val zioSbtVersion = "0.3.10+42-5b06a91e-SNAPSHOT"

addSbtPlugin("dev.zio" % "zio-sbt-ecosystem" % zioSbtVersion)
addSbtPlugin("dev.zio" % "zio-sbt-website"   % zioSbtVersion)
addSbtPlugin("dev.zio" % "zio-sbt-ci"        % zioSbtVersion)

resolvers ++= Resolver.sonatypeOssRepos("public")
