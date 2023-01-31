import V._
import sbtcrossproject.CrossPlugin.autoImport.crossProject

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
  .settings(stdSettings(Scala3, enableSilencer = true))
  .settings(crossProjectSettings)
  .settings(buildInfoSettings("zio.crypto"))
  .settings(enableZIO(ZIOVersion))
  .settings(
    name := "zio-crypto",
    crossScalaVersions := Seq(Scala211, Scala212, Scala213),
    ThisBuild / scalaVersion := Scala213,
    scalaVersion := V.Scala213,
    libraryDependencies ++= Seq(
      "com.google.crypto.tink" % "tink"            % TinkVersion,
      "dev.zio"               %% "izumi-reflect"   % IzumiReflectVersion,
      "dev.zio"               %% "zio-stacktracer" % ZIOStacktracerVersion
    )
  )
  .enablePlugins(BuildInfoPlugin)

lazy val coreJVM = core.jvm
  .settings(dottySettings(Scala3, Scala213))

lazy val gcpKMSJVM = project
  .in(file("zio-crypto-gcpkms"))
  .settings(stdSettings(Scala3))
  .settings(buildInfoSettings("zio.crypto.gcpkms"))
  .settings(
    name := "zio-crypto-gcpkms",
    scalaVersion := V.Scala213
  )
  .dependsOn(coreJVM)
  .settings(dottySettings(Scala3, Scala213))
  .enablePlugins(BuildInfoPlugin)

lazy val awsKMSJVM = project
  .in(file("zio-crypto-awskms"))
  .settings(stdSettings(Scala3))
  .settings(buildInfoSettings("zio.crypto.awskms"))
  .settings(
    name := "zio-crypto-awskms",
    scalaVersion := V.Scala213
  )
  .dependsOn(coreJVM)
  .enablePlugins(BuildInfoPlugin)
  .settings(dottySettings(Scala3, Scala213))

lazy val docs = project
  .in(file("zio-crypto-docs"))
  .enablePlugins(WebsitePlugin)
  .settings(
    scalaVersion := V.Scala213,
    moduleName := "zio-crypto-docs",
    scalacOptions -= "-Yno-imports",
    scalacOptions -= "-Xfatal-warnings",
    projectName := "ZIO Crypto",
    mainModuleName := (coreJVM / moduleName).value,
    projectStage := ProjectStage.Experimental,
    docsPublishBranch := "main",
    ScalaUnidoc / unidoc / unidocProjectFilter := inProjects(coreJVM, awsKMSJVM, gcpKMSJVM),
    libraryDependencies ~= { _.filterNot(_.name contains "mdoc")}
  )
  .dependsOn(coreJVM, awsKMSJVM, gcpKMSJVM)
