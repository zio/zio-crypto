import Versions._
import sbtcrossproject.CrossPlugin.autoImport.crossProject

enablePlugins(ZioSbtEcosystemPlugin, ZioSbtCiPlugin)

inThisBuild(
  List(
    name := "ZIO Crypto",
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

lazy val core = crossProject(JVMPlatform)
  .in(file("zio-crypto"))
  .settings(
    stdSettings(
      name = "zio-crypto",
      enableSilencer = true,
      enableCrossProject = true
    )
  )
  .settings(enableZIO())
  .settings(
    libraryDependencies ++= Seq(
      "com.google.crypto.tink" % "tink"            % tinkVersion,
      "dev.zio"               %% "izumi-reflect"   % izumiReflectVersion,
      "dev.zio"               %% "zio-stacktracer" % zioStacktracerVersion
    )
  )

lazy val coreJVM = core.jvm

lazy val gcpKMSJVM = project
  .in(file("zio-crypto-gcpkms"))
  .settings(stdSettings(name = "zio-crypto-gcpkms"))
  .dependsOn(coreJVM)

lazy val awsKMSJVM = project
  .in(file("zio-crypto-awskms"))
  .settings(stdSettings(name = "zio-crypto-awskms", enableCrossProject = false))
  .dependsOn(coreJVM)

lazy val docs = project
  .in(file("zio-crypto-docs"))
  .settings(
    publish / skip := true,
    moduleName := "zio-crypto-docs",
    scalacOptions -= "-Yno-imports",
    scalacOptions -= "-Xfatal-warnings",
    projectName := (ThisBuild / name).value,
    mainModuleName := (coreJVM / moduleName).value,
    projectStage := ProjectStage.Experimental,
    ScalaUnidoc / unidoc / unidocProjectFilter := inProjects(coreJVM, awsKMSJVM, gcpKMSJVM)
  )
  .dependsOn(coreJVM, awsKMSJVM, gcpKMSJVM)
  .enablePlugins(WebsitePlugin)
