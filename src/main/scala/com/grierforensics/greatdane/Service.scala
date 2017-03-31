// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import java.util.logging.Logger
import javax.ws.rs.WebApplicationException
import javax.ws.rs.core.Response
import javax.ws.rs.ext.{ContextResolver, ExceptionMapper, Provider}

import com.owlike.genson.Genson
import com.owlike.genson.ext.jaxrs.GensonJsonConverter
import com.typesafe.scalalogging.LazyLogging
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.servlet.{ServletContextHandler, ServletHolder}
import org.glassfish.jersey.logging.LoggingFeature
import org.glassfish.jersey.model.ContractProvider
import org.glassfish.jersey.server.ResourceConfig
import org.glassfish.jersey.servlet.ServletContainer
import org.slf4j.bridge.SLF4JBridgeHandler


/** Genson configuration for serializing objects to JSON */
object GensonConfig {
  import com.owlike.genson.{Genson, GensonBuilder, ScalaBundle}

  val genson: Genson = new GensonBuilder().
    useIndentation(true).
    useRuntimeType(true).
    useDateAsTimestamp(true).
    withBundle(ScalaBundle().useOnlyConstructorFields(false)).
    create()
}

/** Provides exception handling for Jersey */
@Provider
class CatchAllExceptionMapper extends ExceptionMapper[Exception] with LazyLogging {
  def toResponse(ex: Exception): Response = {
    ex match {
      case e: WebApplicationException => e.getResponse
      case e: Exception => {
        logger.warn("request failed", ex)
        Response.status(500).entity(s"Server Error: ${ex.getMessage()}").build()
      }
    }
  }
}

/** Provides Genson instance for JSON handling in Jersey */
@Provider
class GensonCustomResolver extends ContextResolver[Genson] {
  override def getContext(clazz: Class[_]): Genson = GensonConfig.genson
}

/**
  * Embedded Jetty/Jersey REST web server
  *
  * See
  *   - https://www.acando.no/thedailypassion/200555/a-rest-service-with-jetty-and-jersey
  *   - http://nikgrozev.com/2014/10/16/rest-with-embedded-jetty-and-jersey-in-a-single-jar-step-by-step/
  *
  * @param engine Engine to use for service
  * @param port HTTP port on which to serve
  */
class Service(engine: Engine, port: Int) extends LazyLogging {
  Service.installLogging()

  private val config = new ResourceConfig
  config.register(new GensonJsonConverter(new GensonCustomResolver), ContractProvider.NO_PRIORITY)
  config.register(new CatchAllExceptionMapper, ContractProvider.NO_PRIORITY)
  config.register(new Resource(engine), ContractProvider.NO_PRIORITY)
  config.register(new LoggingFeature(Logger.getLogger(getClass.getName),
      LoggingFeature.Verbosity.HEADERS_ONLY), ContractProvider.NO_PRIORITY)

  private val servlet = new ServletHolder(new ServletContainer(config))
  private val server = new Server(port)

  private val context = new ServletContextHandler(server, "/")
  context.addServlet(servlet, "/*")

  /** Runs the service indefinitely */
  def run(): Unit = {
    server.start()
    logger.info(s"Listening on port $port")
    server.join()
  }

  def isStarted: Boolean = server.isStarted

  def stop(): Unit = server.stop()
}

object Service extends LazyLogging {

  /** Installs the SLF4J bridge so we can use Logback for logging */
  def installLogging(): Unit = {
    SLF4JBridgeHandler.removeHandlersForRootLogger()
    SLF4JBridgeHandler.install()
    logger.info(s"Logging initialized (DEBUG enabled: ${logger.underlying.isDebugEnabled})")
  }

  def main(args: Array[String]): Unit = {
    val engine = new Engine(Settings.Default.DnsServers:_*)
    logger.info(s"Using DNS addresses: ${Settings.Default.DnsServers.mkString(", ")}")

    val port = Settings.Default.Port
    val service = new Service(engine, port)
    service.run()
  }
}
