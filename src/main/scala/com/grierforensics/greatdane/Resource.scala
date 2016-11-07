// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import javax.ws.rs._
import javax.ws.rs.core.{MediaType, Response}

@Path("/")
@Produces(Array(MediaType.APPLICATION_JSON))
class Resource(engine: Engine) {

  @GET
  @Path("{email}/test")
  def pem(@PathParam("email") email: String): Seq[String] = {
    engine.certs(email).map(_.toString) match {
      case Nil => throw new WebApplicationException(Response.status(404).build())
      case certs => certs
    }
  }

  @GET
  @Path("{email}/test/{id}")
  def pem(@PathParam("email") email: String, @PathParam("id") id: Int): String = {
    engine.certs(email)
      .lift(id)
      .map(_.toString)
      .getOrElse(throw new WebApplicationException(Response.status(404).build()))
  }

  @GET
  @Path("{email}/{format: pem|hex|text}")
  def certsForEmail(@PathParam("email") email: String, @PathParam("format") format: String): Seq[String] = {
    val certs = format match {
      case "pem" => engine.pem(email)
      case "hex" => engine.hex(email)
      case "text" => engine.text(email)
      case _ => throw new WebApplicationException(Response.status(404).build())
    }

    certs match {
      case Nil => throw new WebApplicationException(Response.status(404).build())
      case cs => cs
    }
  }

  @GET
  @Path("{email}/{format: pem|hex|text}/{id}")
  def certsForEmail(@PathParam("email") email: String, @PathParam("format") format: String, @PathParam("id") id: Int): String = {
    certsForEmail(email, format).lift(id).getOrElse(throw new WebApplicationException(Response.status(404).build()))
  }

  @GET
  @Path("{email}/dnsZoneLine")
  def dnsZoneLine(@PathParam("email") email: String): Seq[String] = {
    engine.dnsZoneLines(email) match {
      case Nil => throw new WebApplicationException(Response.status(404).build())
      case ls => ls
    }
  }

  @GET
  @Path("{email}/dnsZoneLine/{id}")
  def dnsZoneLine(@PathParam("email") email: String, @PathParam("id") id: Int): String = {
    dnsZoneLine(email).lift(id).getOrElse(throw new WebApplicationException(Response.status(404).build()))
  }

  @POST
  @Path("{email}/dnsZoneLine")
  def dnsZoneLine(@PathParam("email") email: String, pemEncodedCertificate: String): String = {
    engine.dnsZoneLine(email, pemEncodedCertificate)
  }
}
