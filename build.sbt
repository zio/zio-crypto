import Versions._
import sbtcrossproject.CrossPlugin.autoImport.crossProject

enablePlugins(ZioSbtEcosystemPlugin, ZioSbtCiPlugin)

inThisBuild(
  List(
    name := "ZIO Cache",
    scalaVersion := Scala213,
    crossScalaVersions := Seq(Scala211, Scala212, Scala213, Scala3),
    developers := List(
      Developer(
        "jdegoes",
        "John De Goes",
        "john@degoes.net",
        url("http://degoes.net")
      )
    ),
    ciEnabledBranches := Seq("main"),
    supportedScalaVersions :=
      Map(
        (coreJVM / thisProject).value.id   -> (coreJVM / crossScalaVersions).value,
        (awsKMSJVM / thisProject).value.id -> (awsKMSJVM / crossScalaVersions).value,
        (gcpKMSJVM / thisProject).value.id -> (gcpKMSJVM / crossScalaVersions).value
      )
  )
)

addCommandAlias("testJVM", ";coreJVM/test")

lazy val root = project
  .in(file("."))
  .settings(
    publish / skip := true
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
      packageName = "zio-crypto",
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

lazy val coreJVM = core.jvm

lazy val gcpKMSJVM = project
  .in(file("zio-crypto-gcpkms"))
  .settings(
    stdSettings(packageName = "zio-crypto-gcpkms")
  )
  .dependsOn(coreJVM)

lazy val awsKMSJVM = project
  .in(file("zio-crypto-awskms"))
  .settings(
    stdSettings(
      packageName = "zio-crypto-awskms",
      enableCrossProject = false
    )
  )
  .dependsOn(coreJVM)

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
