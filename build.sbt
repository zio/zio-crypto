import BuildHelper._
import V._

//enablePlugins(EcosystemPlugin)

inThisBuild(
  List(
    scalaVersion := V.Scala213,
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
  .settings(stdSettings)
  .settings(crossProjectSettings)
  .settings(buildInfoSettings("zio.crypto"))
  .settings(Compile / console / scalacOptions ~= { _.filterNot(Set("-Xfatal-warnings")) })
  .settings(
    name := "zio-crypto",
    crossScalaVersions := Seq(Scala211, Scala212, Scala213),
    ThisBuild / scalaVersion := Scala213,
    scalaVersion := V.Scala213,
    libraryDependencies ++= Seq(
      "dev.zio"              %%% "zio"      % ZIOVersion,
      "dev.zio"              %%% "zio-test" % ZIOVersion % "test",
      "com.google.crypto.tink" % "tink"     % TinkVersion
    )
  )
  .settings(testFrameworks := Seq(new TestFramework("zio.test.sbt.ZTestFramework")))
  .enablePlugins(BuildInfoPlugin)

lazy val coreJVM = core.jvm
  .settings(dottySettings)
  .settings(libraryDependencies += "dev.zio" %%% "zio-test-sbt" % ZIOVersion % Test)
  .settings(scalaReflectTestSettings)

lazy val gcpKMSJVM = project
  .in(file("zio-crypto-gcpkms"))
  .settings(stdSettings)
  .settings(buildInfoSettings("zio.crypto.gcpkms"))
  .settings(Compile / console / scalacOptions ~= { _.filterNot(Set("-Xfatal-warnings")) })
  .settings(
    name := "zio-crypto-gcpkms",
    scalaVersion := V.Scala213,
    libraryDependencies ++= Seq(
      "dev.zio"              %%% "zio"              % ZIOVersion,
      "dev.zio"              %%% "zio-test"         % ZIOVersion % "test",
      "com.google.crypto.tink" % "tink-gcpkms"      % TinkVersion,
      "com.google.cloud"       % "google-cloud-kms" % GoogleCloudKMSVersion
    )
  )
  .settings(testFrameworks := Seq(new TestFramework("zio.test.sbt.ZTestFramework")))
  .dependsOn(coreJVM)
  .enablePlugins(BuildInfoPlugin)
  .settings(dottySettings)
  .settings(libraryDependencies += "dev.zio" %%% "zio-test-sbt" % ZIOVersion % Test)
  .settings(scalaReflectTestSettings)

lazy val awsKMSJVM = project
  .in(file("zio-crypto-awskms"))
  .settings(stdSettings)
  .settings(buildInfoSettings("zio.crypto.awskms"))
  .settings(Compile / console / scalacOptions ~= { _.filterNot(Set("-Xfatal-warnings")) })
  .settings(
    name := "zio-crypto-awskms",
    scalaVersion := V.Scala213,
    libraryDependencies ++= Seq(
      "dev.zio"              %%% "zio"              % ZIOVersion,
      "dev.zio"              %%% "zio-test"         % ZIOVersion % "test",
      "com.google.crypto.tink" % "tink-awskms"      % TinkVersion,
      "com.amazonaws"          % "aws-java-sdk-kms" % AWSKMSVersion
    )
  )
  .settings(testFrameworks := Seq(new TestFramework("zio.test.sbt.ZTestFramework")))
  .dependsOn(coreJVM)
  .enablePlugins(BuildInfoPlugin)
  .settings(dottySettings)
  .settings(libraryDependencies += "dev.zio" %%% "zio-test-sbt" % ZIOVersion % Test)
  .settings(scalaReflectTestSettings)

lazy val docs = project
  .in(file("zio-crypto-docs"))
  .settings(
    scalaVersion := V.Scala213,
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
