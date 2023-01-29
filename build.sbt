import BuildHelper._

//enablePlugins(EcosystemPlugin)

inThisBuild(
  List(
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
      "dev.zio"              %%% "zio"      % V.zioVersion,
      "dev.zio"              %%% "zio-test" % V.zioVersion % "test",
      "com.google.crypto.tink" % "tink"     % V.tinkVersion
    )
  )
  .settings(testFrameworks := Seq(new TestFramework("zio.test.sbt.ZTestFramework")))
  .enablePlugins(BuildInfoPlugin)

lazy val coreJVM = core.jvm
  .settings(dottySettings)
  .settings(libraryDependencies += "dev.zio" %%% "zio-test-sbt" % V.zioVersion % Test)
  .settings(scalaReflectTestSettings)

lazy val gcpKMSJVM = project
  .in(file("zio-crypto-gcpkms"))
  .settings(stdSettings("zio-crypto-gcpkms"))
  .settings(buildInfoSettings("zio.crypto.gcpkms"))
  .settings(Compile / console / scalacOptions ~= { _.filterNot(Set("-Xfatal-warnings")) })
  .settings(
    libraryDependencies ++= Seq(
      "dev.zio"              %%% "zio"              % V.zioVersion,
      "dev.zio"              %%% "zio-test"         % V.zioVersion % "test",
      "com.google.crypto.tink" % "tink-gcpkms"      % V.tinkVersion,
      "com.google.cloud"       % "google-cloud-kms" % V.googleCloudKMSVersion
    )
  )
  .settings(testFrameworks := Seq(new TestFramework("zio.test.sbt.ZTestFramework")))
  .dependsOn(coreJVM)
  .enablePlugins(
    BuildInfoPlugin
//    EcosystemPlugin
  )
  .settings(dottySettings)
  .settings(libraryDependencies += "dev.zio" %%% "zio-test-sbt" % V.zioVersion % Test)
  .settings(scalaReflectTestSettings)

lazy val awsKMSJVM = project
  .in(file("zio-crypto-awskms"))
  .settings(stdSettings("zio-crypto-awskms"))
  .settings(buildInfoSettings("zio.crypto.awskms"))
  .settings(Compile / console / scalacOptions ~= { _.filterNot(Set("-Xfatal-warnings")) })
  .settings(
    libraryDependencies ++= Seq(
      "dev.zio"              %%% "zio"              % V.zioVersion,
      "dev.zio"              %%% "zio-test"         % V.zioVersion % "test",
      "com.google.crypto.tink" % "tink-awskms"      % V.tinkVersion,
      "com.amazonaws"          % "aws-java-sdk-kms" % V.awsKMSVersion
    )
  )
  .settings(testFrameworks := Seq(new TestFramework("zio.test.sbt.ZTestFramework")))
  .dependsOn(coreJVM)
  .enablePlugins(
    BuildInfoPlugin
//    EcosystemPlugin
  )
  .settings(dottySettings)
  .settings(libraryDependencies += "dev.zio" %%% "zio-test-sbt" % V.zioVersion % Test)
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
  .enablePlugins(
    WebsitePlugin,
//    EcosystemPlugin
  )
