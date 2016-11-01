name := "engine"

version := "1.0"

scalaVersion := "2.11.8"

packAutoSettings

libraryDependencies ++= Seq(
  "com.typesafe" % "config" % "1.3.1",

  "ch.qos.logback" %  "logback-classic" % "1.1.7",
  "com.typesafe.scala-logging" % "scala-logging_2.11" % "3.5.0",

  "com.owlike" % "genson-scala" % "1.2",

  "javax.mail" % "javax.mail-api" % "1.5.6",

  "org.eclipse.jetty" % "jetty-server" % "9.3.13.v20161014",
  "org.eclipse.jetty" % "jetty-servlet" % "9.3.13.v20161014",

  "org.glassfish.jersey.core" % "jersey-server" % "2.24",
  "org.glassfish.jersey.containers" % "jersey-container-servlet" % "2.24",
  "org.glassfish.jersey.containers" % "jersey-container-jetty-http" % "2.24"
)
    