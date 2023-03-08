import BuildHelper._

inThisBuild(
  List(
    organization := "dev.zio",
    homepage := Some(url("https://zio.dev/zio-crypto/")),
    licenses := List("Apache-2.0" -> url("http://www.apache.org/licenses/LICENSE-2.0")),
    developers := List(
      Developer(
        "jdegoes",
        "John De Goes",
        "john@degoes.net",
        url("http://degoes.net")
      )
    )
  )
)

addCommandAlias("fix", "; all compile:scalafix test:scalafix; all scalafmtSbt scalafmtAll")
addCommandAlias("check", "; scalafmtSbtCheck; scalafmtCheckAll; compile:scalafix --check; test:scalafix --check")

addCommandAlias(
  "testJVM",
  ";coreJVM/test"
)

val googleCloudKMSVersion = "2.15.0"
val tinkVersion           = "1.7.0"
val zioVersion            = "2.0.0"
val awsKMSVersion         = "1.12.421"

lazy val root = project
  .in(file("."))
  .settings(publish / skip := true)
  .aggregate(
    coreJVM,
    gcpKMSJVM,
    awsKMSJVM,
    docs
  )

lazy val core = crossProject(JVMPlatform)
  .in(file("zio-crypto"))
  .settings(stdSettings("zio-crypto"))
  .settings(crossProjectSettings)
  .settings(buildInfoSettings("zio.crypto"))
  .settings(Compile / console / scalacOptions ~= { _.filterNot(Set("-Xfatal-warnings")) })
  .settings(
    libraryDependencies ++= Seq(
      "dev.zio"              %%% "zio"      % zioVersion,
      "dev.zio"              %%% "zio-test" % zioVersion % "test",
      "com.google.crypto.tink" % "tink"     % tinkVersion
    )
  )
  .settings(testFrameworks := Seq(new TestFramework("zio.test.sbt.ZTestFramework")))
  .enablePlugins(BuildInfoPlugin)

lazy val coreJVM = core.jvm
  .settings(dottySettings)
  .settings(libraryDependencies += "dev.zio" %%% "zio-test-sbt" % zioVersion % Test)
  .settings(scalaReflectTestSettings)

lazy val gcpKMSJVM = project
  .in(file("zio-crypto-gcpkms"))
  .settings(stdSettings("zio-crypto-gcpkms"))
  .settings(buildInfoSettings("zio.crypto.gcpkms"))
  .settings(Compile / console / scalacOptions ~= { _.filterNot(Set("-Xfatal-warnings")) })
  .settings(
    libraryDependencies ++= Seq(
      "dev.zio"              %%% "zio"              % zioVersion,
      "dev.zio"              %%% "zio-test"         % zioVersion % "test",
      "com.google.crypto.tink" % "tink-gcpkms"      % tinkVersion,
      "com.google.cloud"       % "google-cloud-kms" % googleCloudKMSVersion
    )
  )
  .settings(testFrameworks := Seq(new TestFramework("zio.test.sbt.ZTestFramework")))
  .dependsOn(coreJVM)
  .enablePlugins(BuildInfoPlugin)
  .settings(dottySettings)
  .settings(libraryDependencies += "dev.zio" %%% "zio-test-sbt" % zioVersion % Test)
  .settings(scalaReflectTestSettings)

lazy val awsKMSJVM = project
  .in(file("zio-crypto-awskms"))
  .settings(stdSettings("zio-crypto-awskms"))
  .settings(buildInfoSettings("zio.crypto.awskms"))
  .settings(Compile / console / scalacOptions ~= { _.filterNot(Set("-Xfatal-warnings")) })
  .settings(
    libraryDependencies ++= Seq(
      "dev.zio"              %%% "zio"              % zioVersion,
      "dev.zio"              %%% "zio-test"         % zioVersion % "test",
      "com.google.crypto.tink" % "tink-awskms"      % tinkVersion,
      "com.amazonaws"          % "aws-java-sdk-kms" % awsKMSVersion
    )
  )
  .settings(testFrameworks := Seq(new TestFramework("zio.test.sbt.ZTestFramework")))
  .dependsOn(coreJVM)
  .enablePlugins(BuildInfoPlugin)
  .settings(dottySettings)
  .settings(libraryDependencies += "dev.zio" %%% "zio-test-sbt" % zioVersion % Test)
  .settings(scalaReflectTestSettings)

lazy val docs = project
  .in(file("zio-crypto-docs"))
  .settings(
    moduleName := "zio-crypto-docs",
    scalacOptions -= "-Yno-imports",
    scalacOptions -= "-Xfatal-warnings",
    projectName := "ZIO Crypto",
    mainModuleName := (coreJVM / moduleName).value,
    projectStage := ProjectStage.Experimental,
    docsPublishBranch := "main",
    ScalaUnidoc / unidoc / unidocProjectFilter := inProjects(coreJVM, awsKMSJVM, gcpKMSJVM)
  )
  .dependsOn(coreJVM, awsKMSJVM, gcpKMSJVM)
  .enablePlugins(WebsitePlugin)
