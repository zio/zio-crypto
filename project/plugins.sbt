addSbtPlugin("ch.epfl.scala"      % "sbt-bloop"                     % "1032048a")
addSbtPlugin("com.geirsson"       % "sbt-ci-release"                % "1.5.7")
addSbtPlugin("com.github.cb372"   % "sbt-explicit-dependencies"     % "0.2.16")
addSbtPlugin("org.scala-js"       % "sbt-scalajs"                   % "1.13.0")
addSbtPlugin("org.scala-native"   % "sbt-scala-native"              % "0.4.10")
addSbtPlugin("pl.project13.scala" % "sbt-jcstress"                  % "0.2.0")
addSbtPlugin("pl.project13.scala" % "sbt-jmh"                       % "0.4.3")
addSbtPlugin("dev.zio"            % "zio-sbt-website"               % "0.3.6")
addSbtPlugin("dev.zio"            % "zio-sbt-ecosystem"             % "0.3.10+3-126eef36-SNAPSHOT")

libraryDependencies += "org.snakeyaml" % "snakeyaml-engine" % "2.6"

resolvers += Resolver.sonatypeRepo("public")
