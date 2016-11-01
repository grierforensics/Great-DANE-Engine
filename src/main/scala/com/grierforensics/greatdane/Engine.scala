// Copyright (C) 2016 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

/** Core DANE SMIMEA Engine.
  *
  * Adds and retrieves DANE SMIMEA records to/from configured DNS server.
  *
  * @param dnsServer DNS Server address
  */
class Engine(dnsServer: String) {
  val certdb = Map(
    "joe" -> List("hello", "world", "goodbye", "all")
  )

  def certs(email: String): List[String] = {
    certdb.getOrElse(email, List())
  }
}
