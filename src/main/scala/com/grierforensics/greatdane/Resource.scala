// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import javax.ws.rs._
import javax.ws.rs.core.{MediaType, Response}

@Path("/")
@Produces(Array(MediaType.APPLICATION_JSON))
class Resource(engine: Engine) {

  val genson = GensonConfig.genson

  /** Retrieves all certificates for the given email address.
    *
    * @param email email address to search for
    * @param format requested format of retrieved certificates
    * @return all found certificates or 404 if none found
    */
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

  /** Retrieves a certificate for the given email address.
    *
    * @param email email address to search for
    * @param format requested format of retrieved certificate
    * @param id index of certificate requested
    * @return certificate in requested format or 404 if not found
    */
  @GET
  @Path("{email}/{format: pem|hex|text|dnsZoneLine}/{id}")
  def certsForEmail(@PathParam("email") email: String, @PathParam("format") format: String, @PathParam("id") id: Int): String = {
    val cert = certsForEmail(email, format).lift(id).getOrElse(throw new WebApplicationException(Response.status(404).build()))
    genson.serialize(cert)
  }

  /** Creates a DANE Entry for the given email address and POSTed certificate.
    * Returns the corresponding DNS zone line.
    *
    * @param email email address to encode
    * @param pemEncodedCertificate certificate to use in DANE entry
    * @return
    */
  @POST
  @Path("{email}/dnsZoneLineForCert")
  def dnsZoneLine(@PathParam("email") email: String, pemEncodedCertificate: String): String = {
    val zoneLine = engine.dnsZoneLine(email, pemEncodedCertificate)
    genson.serialize(zoneLine)
  }
}
