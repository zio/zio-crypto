import Versions._
import sbtcrossproject.CrossPlugin.autoImport.crossProject

enablePlugins(ZioSbtEcosystemPlugin, ZioSbtCiPlugin)

inThisBuild(
  List(
    name := "ZIO Crypto",
    zioVersion := "2.0.0",
    crossScalaVersions -= scala211.value,
    developers := List(
      Developer(
        "jdegoes",
        "John De Goes",
        "john@degoes.net",
        url("http://degoes.net")
      )
    ),
    ciEnabledBranches := Seq("main")
  )
)

lazy val root = project
  .in(file("."))
  .settings(
    publish / skip := true
  )
  .aggregate(
    `zio-crypto`.jvm,
    `zio-crypto-gcpkms`,
    `zio-crypto-awskms`,
    docs
  )

lazy val `zio-crypto` = crossProject(JVMPlatform)
  .settings(
    stdSettings(
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

lazy val `zio-crypto-gcpkms` = project
  .settings(stdSettings())
  .dependsOn(`zio-crypto`.jvm)

lazy val `zio-crypto-awskms` = project
  .settings(stdSettings(enableCrossProject = false))
  .dependsOn(`zio-crypto`.jvm)

lazy val docs = project
  .in(file("zio-crypto-docs"))
  .settings(
    publish / skip := true,
    moduleName := "zio-crypto-docs",
    scalacOptions -= "-Yno-imports",
    scalacOptions -= "-Xfatal-warnings",
    projectName := (ThisBuild / name).value,
    mainModuleName := (`zio-crypto`.jvm / moduleName).value,
    projectStage := ProjectStage.Experimental,
    ScalaUnidoc / unidoc / unidocProjectFilter := inProjects(`zio-crypto`.jvm, `zio-crypto-awskms`, `zio-crypto-gcpkms`)
  )
  .dependsOn(`zio-crypto`.jvm, `zio-crypto-awskms`, `zio-crypto-gcpkms`)
  .enablePlugins(WebsitePlugin)
