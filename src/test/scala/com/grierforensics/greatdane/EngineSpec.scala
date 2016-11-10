// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import org.scalatest.FlatSpec

class EngineSpec extends FlatSpec {

  import TestValues._

  "An Engine" should "properly encode and decode PEM-format certificates" in {
    val decoded = Engine.fromPem(Entry.pem)
    val encoded = Engine.toPem(decoded)
    assert(Entry.certHolder.getEncoded.deep == decoded.getEncoded.deep)
    assert(Entry.pem == encoded)
  }

  it should "properly Hex-encode and -decode DER-format certificates" in {
    val decoded = Engine.fromHex(Entry.hex)
    val encoded = Engine.toHex(decoded)
    assert(Entry.certHolder.getEncoded.deep == decoded.getEncoded.deep)
    assert(Entry.hex == encoded)
  }

  it should "correctly fetch all certificates" in {
    val engine = new TestEngine
    val certs = engine.fetchCertificates(Entry.email)
    assert(certs.length == 3)
    certs.foreach(cert => assert(cert == Entry.cert))
  }

  it should "return an empty Seq if no certificates are found" in {
    val engine = new TestEngine
    val email = "dev@grierforensics.com"

    assert(engine.fetchCertificates(email).isEmpty)
    assert(engine.text(email).isEmpty)
    assert(engine.hex(email).isEmpty)
    assert(engine.pem(email).isEmpty)
    assert(engine.dnsZoneLines(email).isEmpty)
  }

  it should "return all certificates in text form" in {
    val engine = new TestEngine
    val certs = engine.text(Entry.email)
    assert(certs.length == 3)
    certs.foreach(text => assert(text == Entry.text))
  }

  it should "return all certificates in hex form" in {
    val engine = new TestEngine
    val certs = engine.hex(Entry.email)
    assert(certs.length == 3)
    certs.foreach(hex => assert(hex == Entry.hex))
  }

  it should "return all certificates in pem form" in {
    val engine = new TestEngine
    val certs = engine.pem(Entry.email)
    assert(certs.length == 3)
    certs.foreach(pem => assert(pem == Entry.pem))
  }

  it should "return valid DNS Zone Lines for each certificate" in {
    val engine = new TestEngine
    val lines = engine.dnsZoneLines(Entry.email)
    assert(lines.length == 3)
    lines.foreach(line => assert(line == Entry.zoneLine))
  }

  it should "create a valid DNS Zone Line" in {
    val engine = new TestEngine
    val linePem = engine.dnsZoneLine(Entry.email, Entry.pem)
    val lineDer = engine.dnsZoneLine(Entry.email, Entry.bytes)
    assert(linePem == Entry.zoneLine)
    assert(lineDer == Entry.zoneLine)
  }
}
