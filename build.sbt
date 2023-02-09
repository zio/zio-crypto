import V._
import sbtcrossproject.CrossPlugin.autoImport.crossProject

enablePlugins(EcosystemPlugin)

inThisBuild(
  List(
    scalaVersion := Scala213,
    organization := "dev.zio",
    homepage := Some(url("https://zio.dev/zio-crypto/")),
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

addCommandAlias("testJVM", ";coreJVM/test")

lazy val root = project
  .in(file("."))
  .settings(
    publish / skip := true,
    ciEnabledBranches := Seq("main"),
    supportedScalaVersions :=
      Map(
        (coreJVM / thisProject).value.id   -> (coreJVM / crossScalaVersions).value,
        (awsKMSJVM / thisProject).value.id -> (awsKMSJVM / crossScalaVersions).value,
        (gcpKMSJVM / thisProject).value.id -> (gcpKMSJVM / crossScalaVersions).value
      )
  )
  .aggregate(
    coreJVM,
    gcpKMSJVM,
    awsKMSJVM,
    docs
  )
  .enablePlugins(ZioSbtCiPlugin)

lazy val core = crossProject(JVMPlatform)
  .in(file("zio-crypto"))
  .settings(
    stdSettings(
      name = "zio-crypto",
      packageName = "zio.crypto",
      scalaVersion = Scala213,
      crossScalaVersions = Seq(Scala211, Scala212, Scala213, Scala3),
      enableSilencer = true,
      enableCrossProject = true
    )
  )
  .settings(enableZIO(ZIOVersion, enableTesting = true))
  .settings(
    libraryDependencies ++= Seq(
      "com.google.crypto.tink" % "tink"            % TinkVersion,
      "dev.zio"               %% "izumi-reflect"   % IzumiReflectVersion,
      "dev.zio"               %% "zio-stacktracer" % ZIOStacktracerVersion
    )
  )
  .enablePlugins(EcosystemPlugin)

lazy val coreJVM = core.jvm

lazy val gcpKMSJVM = project
  .in(file("zio-crypto-gcpkms"))
  .settings(
    stdSettings(
      name = "zio-crypto-gcpkms",
      packageName = "zio.crypto.gcpkms",
      scalaVersion = Scala213,
      crossScalaVersions = Seq(Scala211, Scala212, Scala213, Scala3)
    )
  )
  .dependsOn(coreJVM)
  .enablePlugins(EcosystemPlugin)

lazy val awsKMSJVM = project
  .in(file("zio-crypto-awskms"))
  .settings(
    stdSettings(
      name = "zio-crypto-awskms",
      packageName = "zio.crypto.awskms",
      scalaVersion = Scala213,
      crossScalaVersions = Seq(Scala211, Scala212, Scala213, Scala3),
      enableCrossProject = false
    )
  )
  .dependsOn(coreJVM)
  .enablePlugins(EcosystemPlugin)

lazy val docs = project
  .in(file("zio-crypto-docs"))
  .settings(
    publish / skip := true,
    scalaVersion := Scala213,
    moduleName := "zio-crypto-docs",
    scalacOptions -= "-Yno-imports",
    scalacOptions -= "-Xfatal-warnings",
    projectName := "ZIO Crypto",
    mainModuleName := (coreJVM / moduleName).value,
    projectStage := ProjectStage.Experimental,
    ScalaUnidoc / unidoc / unidocProjectFilter := inProjects(coreJVM, awsKMSJVM, gcpKMSJVM),
    libraryDependencies ~= { _.filterNot(_.name contains "mdoc") }
  )
  .dependsOn(coreJVM, awsKMSJVM, gcpKMSJVM)
  .enablePlugins(WebsitePlugin)
