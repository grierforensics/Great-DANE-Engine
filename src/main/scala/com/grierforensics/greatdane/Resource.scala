// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import javax.ws.rs._
import javax.ws.rs.core.{MediaType, Response}

@Path("/")
@Produces(Array(MediaType.APPLICATION_JSON))
class Resource(engine: Engine) {

  val genson = GensonConfig.genson

  @GET
  @Path("{email}/{format: pem|hex|text|dnsZoneLine}")
  def certsForEmail(@PathParam("email") email: String, @PathParam("format") format: String): Seq[String] = {
    val certs = format match {
      case "pem" => engine.pem(email)
      case "hex" => engine.hex(email)
      case "text" => engine.text(email)
      case "dnsZoneLine" => engine.dnsZoneLines(email)
      case _ => throw new WebApplicationException(Response.status(404).build())
    }

    certs match {
      case Nil => throw new WebApplicationException(Response.status(404).build())
      case cs => cs
    }
  }

  @GET
  @Path("{email}/{format: pem|hex|text|dnsZoneLine}/{id}")
  def certsForEmail(@PathParam("email") email: String, @PathParam("format") format: String, @PathParam("id") id: Int): String = {
    val cert = certsForEmail(email, format).lift(id).getOrElse(throw new WebApplicationException(Response.status(404).build()))
    genson.serialize(cert)
  }

  @POST
  @Path("{email}/dnsZoneLineForCert")
  def dnsZoneLine(@PathParam("email") email: String, pemEncodedCertificate: String): String = {
    val zoneLine = engine.dnsZoneLine(email, pemEncodedCertificate)
    genson.serialize(zoneLine)
  }
}
