import org.portablescala.sbtplatformdeps.PlatformDepsPlugin.autoImport._
import sbt.Keys._
import sbt.{ Console => _, _ }

object BuildHelper {
  import V._

  val scalaReflectSettings = Seq(
    libraryDependencies ++= Seq("dev.zio" %%% "izumi-reflect" % "2.2.4")
  )

  val scalaReflectTestSettings: List[Setting[_]] = List(
    libraryDependencies ++= {
      if (scalaVersion.value == Scala3)
        Seq("org.scala-lang" % "scala-reflect" % Scala213           % Test)
      else
        Seq("org.scala-lang" % "scala-reflect" % scalaVersion.value % Test)
    }
  )
}
