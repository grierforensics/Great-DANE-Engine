// Copyright (C) 2016 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import javax.mail.internet.InternetAddress
import javax.ws.rs.WebApplicationException
import javax.ws.rs.core.Response
import javax.ws.rs.ext.{ContextResolver, ExceptionMapper, Provider}

import com.owlike.genson.Genson
import com.owlike.genson.ext.jaxrs.GensonJsonConverter
import com.typesafe.scalalogging.LazyLogging
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.servlet.{ServletContextHandler, ServletHolder}
import org.glassfish.jersey.model.ContractProvider
import org.glassfish.jersey.server.ResourceConfig
import org.glassfish.jersey.servlet.ServletContainer


/** Genson configuration for serializing objects to JSON */
object GensonConfig {
  import com.owlike.genson.stream.{ObjectReader, ObjectWriter}
  import com.owlike.genson.{Context, Converter, Genson, GensonBuilder, ScalaBundle}

  val genson: Genson = new GensonBuilder().
    useIndentation(true).
    useRuntimeType(true).
    useDateAsTimestamp(true).
    withConverters(new InternetAddressConverter).
    withBundle(ScalaBundle().useOnlyConstructorFields(false)).
    create()

  class InternetAddressConverter extends Converter[InternetAddress] {
    override def serialize(ia: InternetAddress, writer: ObjectWriter, ctx: Context): Unit = {
      writer.writeValue(ia.toString)
    }

    override def deserialize(reader: ObjectReader, ctx: Context): InternetAddress = {
      new InternetAddress(reader.valueAsString())
    }
  }
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
  override def getContext(`type`: Class[_]): Genson = GensonConfig.genson
}

/**
  * Embedded Jetty/Jersey REST web server
  *
  * See
  *   - https://www.acando.no/thedailypassion/200555/a-rest-service-with-jetty-and-jersey
  *   - http://nikgrozev.com/2014/10/16/rest-with-embedded-jetty-and-jersey-in-a-single-jar-step-by-step/
  */
object Service extends LazyLogging {

  val dnsServers = Settings.Default.DnsServers
  val DaneEngine = new Engine(dnsServers:_*)
  logger.info(s"Using DNS addresses: ${dnsServers.mkString(", ")}")

  def main(args: Array[String]): Unit = {
    val port = Settings.Default.Port

    val config = new ResourceConfig
    config.register(new GensonJsonConverter(new GensonCustomResolver), ContractProvider.NO_PRIORITY)
    config.register(new CatchAllExceptionMapper, ContractProvider.NO_PRIORITY)
    config.register(classOf[Resource])

    val servlet = new ServletHolder(new ServletContainer(config))
    val server = new Server(port)

    val context = new ServletContextHandler(server, "/")
    context.addServlet(servlet, "/*")

    try {
      server.start()
      logger.info(s"Listening on port $port")
      server.join()
    } finally {
      server.destroy()
    }
  }
}
