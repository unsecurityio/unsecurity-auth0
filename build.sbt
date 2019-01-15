import sbt.Keys.libraryDependencies

organization := "io.unsecurity"

name := "unsecurity-auth0"

version := "0.1"

scalaVersion := "2.12.8"

scalacOptions := Seq(
  "-deprecation",
  "-Ypartial-unification",
  "-language:higherKinds",
  "-Ywarn-value-discard"
)

val circeVersion = "0.10.1"
val http4sVersion = "0.20.0-M4"
val directivesVersion = "0.20.0-M4-1"

libraryDependencies := Seq(
  "io.unsecurity" %% "unsecurity-core" % "0.1",
  "org.scalatest" %% "scalatest" % "3.0.5" % Test
)
