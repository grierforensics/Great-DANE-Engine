// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import java.net.{HttpURLConnection, URL}

import com.owlike.genson.defaultGenson._
import org.apache.commons.io.IOUtils
import org.scalatest.FlatSpec

class ResourceSpec extends FlatSpec {
  import TestValues._

  // Start test service on localhost, which will be shutdown when JVM closes
  val port = 53535
  val service = new Service(new TestEngine, port)
  new Thread() {
    override def run(): Unit = {
      service.run()
    }
  }.start()

  // Wait to ensure service is up and running
  while (!service.isStarted) {
    Thread.sleep(200)
  }

  val baseUrl = s"http://localhost:$port"

  /** Performs an HTTP GET on the given URL
    *
    * @param url URL to GET
    * @return (HTTP response code, JSON response body)
    */
  def get(url: String): (Int, String) = {
    val conn = new URL(url).openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("GET")
    conn.setRequestProperty("Accept", "application/json")

    val code = conn.getResponseCode
    val json = if (code == 200) IOUtils.toString(conn.getInputStream, "utf-8") else ""
    (code, json)
  }

  /** Retrieves a JSON sequence given an email and type of resource requested */
  def makeUrl(email: String, kind: String): String = {
    baseUrl + s"/${email}/$kind"
  }

  /** Retrieves a JSON resource given an email and type of resource requested */
  def makeUrl(email: String, kind: String, index: Int): String = {
    makeUrl(email, kind) + s"/$index"
  }

  def post(url: String, input: String): (Int, String) = {
    val conn = new URL(url).openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("POST")
    conn.setRequestProperty("Accept", "application/json")
    conn.setDoOutput(true)

    IOUtils.write(input, conn.getOutputStream, "utf-8")

    val code = conn.getResponseCode
    val json = if (code == 200) IOUtils.toString(conn.getInputStream, "utf-8") else ""
    (code, json)
  }

  "The Resource" should "return HTTP 4XX for invalid endpoints" in {
    val (code, _) = get(makeUrl(Entry.email, "der"))
    assert(code >= 400 && code < 500)
  }

  it should "return valid JSON containing all text-format certificates" in {
    val (code, json) = get(makeUrl(Entry.email, "text"))
    assert(code == 200)
    val texts = fromJson[Seq[String]](json)
    assert(texts.length == 3)
    texts.foreach(text => assert(text == Entry.text))
  }

  it should "return valid JSON containing all hex-format certificates" in {
    val (code, json) = get(makeUrl(Entry.email, "hex"))
    assert(code == 200)
    val hexs = fromJson[Seq[String]](json)
    assert(hexs.length == 3)
    hexs.foreach(hex => assert(hex == Entry.hex))
  }

  it should "return valid JSON containing all pem-format certificates" in {
    val (code, json) = get(makeUrl(Entry.email, "pem"))
    assert(code == 200)
    val pems = fromJson[Seq[String]](json)
    assert(pems.length == 3)
    pems.foreach(pem => assert(pem == Entry.pem))
  }

  it should "return valid JSON containing all corresponding DNS zone lines" in {
    val (code, json) = get(makeUrl(Entry.email, "dnsZoneLine"))
    assert(code == 200)
    val lines = fromJson[Seq[String]](json)
    assert(lines.length == 3)
    lines.foreach(line => assert(line == Entry.zoneLine))
  }

  it should "return a single text-format certificate as requested" in {
    val (code, json) = get(makeUrl(Entry.email, "text", 1))
    assert(code == 200)
    val text = fromJson[String](json)
    assert(text == Entry.text)
  }

  it should "return a single hex-format certificate as requested" in {
    val (code, json) = get(makeUrl(Entry.email, "hex", 1))
    assert(code == 200)
    val hex = fromJson[String](json)
    assert(hex == Entry.hex)
  }

  it should "return a single pem-format certificate as requested" in {
    val (code, json) = get(makeUrl(Entry.email, "pem", 1))
    assert(code == 200)
    val pem = fromJson[String](json)
    assert(pem == Entry.pem)
  }

  it should "return a single DNS zone line as requested" in {
    val (code, json) = get(makeUrl(Entry.email, "dnsZoneLine", 1))
    assert(code == 200)
    val line = fromJson[String](json)
    assert(line == Entry.zoneLine)
  }

  it should "return a 404 if no certificates are found" in {
    Seq("text", "hex", "pem", "dnsZoneLine").foreach { kind =>
      val (code, _) = get(makeUrl("dev@grierforensics.com", kind))
      assert(code == 404, kind)
    }
  }

  it should "return a 404 if a specific certificate does not exist" in {
    Seq("text", "hex", "pem", "dnsZoneLine").foreach { kind =>
      val (code0, _) = get(makeUrl("dev@grierforensics.com", kind, 0))
      assert (code0 == 404, kind)

      val (code1, _) = get(makeUrl(Entry.email, kind, TestDaneEntryCount))
      assert(code1 == 404, kind)

      val (code2, _) = get(makeUrl(Entry.email, kind, -1))
      assert(code2 == 404, kind)
    }
  }

  it should "create a valid DNS zone line given a PEM-format certificate" in {
    val (code, json) = post(makeUrl(Entry.email, "dnsZoneLineForCert"), Entry.pem)
    assert(code == 200)
    val line = fromJson[String](json)
    assert(line == Entry.zoneLine)
  }

}
