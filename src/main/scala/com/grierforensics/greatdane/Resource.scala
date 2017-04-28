// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import javax.ws.rs._
import javax.ws.rs.core.{MediaType, Response}

case class CertificateResponse(certificates: Seq[CertificateDetails])
case class ZoneLineResponse(zoneLines: Seq[String])

@Path("/")
@Produces(Array(MediaType.APPLICATION_JSON))
class Resource(engine: Engine) {

  val genson = GensonConfig.genson

  /** Provides an endpoint for verifying connectivity
    *
    * @return "pong"
    */
  @GET
  @Path("/ping")
  def ping: String = "pong"

  /** Retrieves all certificates for the given email address.
    *
    * @param email email address to search for
    * @param format requested format of retrieved certificates
    * @return all found certificates or 404 if none found
    */
  @GET
  @Path("{email}/{format: pem|hex|text}")
  def certsForEmail(@PathParam("email") email: String, @PathParam("format") format: String): CertificateResponse = {
    val certs: Seq[CertificateDetails] = format match {
      case "pem" => engine.pem(email)
      case "hex" => engine.hex(email)
      case "text" => engine.text(email)
      case _ => throw new WebApplicationException(Response.status(404).build())
    }

    certs match {
      case Nil => throw new WebApplicationException(Response.status(404).build())
      case cs => CertificateResponse(cs)
    }
  }

  /** Retrieves SMIMEA records from the DNS for the given email address
    *
    * @param email email address to search for
    * @return all found SMIMEA records or 404 if none found
    */
  @GET
  @Path("{email}/dnsZoneLine")
  def dnsZoneLinesForEmail(@PathParam("email") email: String): ZoneLineResponse = {
    engine.dnsZoneLines(email) match {
      case Nil => throw new WebApplicationException(Response.status(404).build())
      case zl => ZoneLineResponse(zl)
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
  @Path("{email}/{format: pem|hex|text}/{id}")
  def certForEmail(@PathParam("email") email: String, @PathParam("format") format: String, @PathParam("id") id: Int): CertificateDetails = {
    /*val cert = */certsForEmail(email, format).certificates.lift(id).getOrElse(throw new WebApplicationException(Response.status(404).build()))
    //genson.serialize(cert)
  }

  /** Retrieves a SMIMEA record from the DNS for the given email address
    *
    * @param email email address to search for
    * @param id index of SMIMEA record requested
    * @return SMIMEA record or 404 if none found
    */
  @GET
  @Path("{email}/dnsZoneLine/{id}")
  def dnsZoneLineForEmail(@PathParam("email") email: String, @PathParam("id") id: Int): String = {
    val zoneLine = dnsZoneLinesForEmail(email).zoneLines.lift(id).getOrElse(throw new WebApplicationException(Response.status(404).build()))
    genson.serialize(zoneLine)
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
