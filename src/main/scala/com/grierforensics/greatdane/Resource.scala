// Copyright (C) 2016 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import javax.ws.rs._
import javax.ws.rs.core.{MediaType, Response}

@Path("/")
@Produces(Array(MediaType.APPLICATION_JSON))
class Resource {

  @GET
  @Path("{email}/pem")
  def pem(@PathParam("email") email: String): Seq[String] = {
    Service.DaneEngine.certs(email).map(_.toString) match {
      case Nil => throw new WebApplicationException(Response.status(404).build())
      case certs => certs
    }
  }

  @GET
  @Path("{email}/pem/{id}")
  def pem(@PathParam("email") email: String, @PathParam("id") id: Int): String = {
    Service.DaneEngine.certs(email)
      .lift(id)
      .map(_.toString)
      .getOrElse(throw new WebApplicationException(Response.status(404).build()))
  }
}
