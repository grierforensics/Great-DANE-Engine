// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import java.security.cert.X509Certificate
import java.util

import com.grierforensics.greatdane.Engine.DaneEntryFetcher
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.dane.{DANEEntry, DANEEntryFetcher, DANEEntryFetcherFactory, DANEEntrySelectorFactory}
import org.bouncycastle.util.encoders.Hex
import org.scalatest.FlatSpec

class EngineSpec extends FlatSpec {
  object testEntry {
    val email = "dev@dev-grierforensics.com"

    val domain = new DANEEntrySelectorFactory(Engine.TruncatingDigestCalculator)
      .createSelector(email)
      .getDomainName

    val pem = """-----BEGIN CERTIFICATE-----
                       |MIIDZTCCAk2gAwIBAgIJAM07b+H5nmJNMA0GCSqGSIb3DQEBBQUAMEkxHDAaBgNV
                       |BAMME0RBTkUgU01JTUVBIFRvb2xzZXQxKTAnBgkqhkiG9w0BCQEWGmRldkBkZXYt
                       |Z3JpZXJmb3JlbnNpY3MuY29tMB4XDTE1MDcxNTEyMjcxOVoXDTI1MDcyMjEyMjcx
                       |OVowSTEcMBoGA1UEAwwTREFORSBTTUlNRUEgVG9vbHNldDEpMCcGCSqGSIb3DQEJ
                       |ARYaZGV2QGRldi1ncmllcmZvcmVuc2ljcy5jb20wggEiMA0GCSqGSIb3DQEBAQUA
                       |A4IBDwAwggEKAoIBAQCwGd5+X3BHh+xaEZdtYPF/KTXc9g6gdO8MoNY5uFyJR4KB
                       |8wn5DSd3S2j3x/R9KDtruSTWrEAz9F06RtlgNQClD+vXkj4a7MuuDa+Pep4tfiCq
                       |5SUPXUzBSH3dONo3WsYx+5e7tLZev6S12c586ytAh9zzbq3mr1ymkaC2FsZqt1re
                       |1GgfM3Zp9/JbB0866jwMwnY70sV739RTwymHy1s3t2ZsvOQ5DW3pPr4WFacgDY/D
                       |Nb+E5Xb1hebdfflYTJDAto+KzXA4DungGCaD9t2AZf2hoxxYsWkmx6jzF2oR8O3S
                       |SzeA5/iY+oFpiLAKwgl3Q9YKkCfzFVl+0zt0UhDTAgMBAAGjUDBOMB0GA1UdDgQW
                       |BBTjVB8q6Qeo40f9UNmijl4OZPJFHzAfBgNVHSMEGDAWgBTjVB8q6Qeo40f9UNmi
                       |jl4OZPJFHzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4IBAQAiJjBuZyus
                       |vhLNZelqLEk28Fo+advVDPOEopyHF1NwSfmEwFgHS0Pzike3soeAK5ZpF+Aqjze2
                       |1qmXiJBaaEKHyZgmTZZJ14xr3JVd6AseLTsml3YUi836vtaxW9EqSv1WTMgA/afG
                       |+7d2GI8rU+4phrvw5Udswl3Kr57pA5jt64dQgf+QUVsNPDhvKKcJJdXKK0enP9/R
                       |nvC+7ni+/Nz9jPMtsLTzkCAuq1a36bgJfEgLZ7c/HK2O/MQbRlfynt2o9JINxvJ5
                       |KM9C7OwFk5n7le0/IBxrSwUWsqf8nWrnZpcLrPJUTTcfCbVe7wpH8VA465VtP7jS
                       |y5AX0dF7FK+H
                       |-----END CERTIFICATE-----
                       |""".stripMargin

    val hex = """308203653082024da003020102020900cd3b6fe1f99e624d300d06092a864886f70d01010505003049311c301a06035504030c1344414e4520534d494d454120546f6f6c7365743129302706092a864886f70d010901161a646576406465762d6772696572666f72656e736963732e636f6d301e170d3135303731353132323731395a170d3235303732323132323731395a3049311c301a06035504030c1344414e4520534d494d454120546f6f6c7365743129302706092a864886f70d010901161a646576406465762d6772696572666f72656e736963732e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100b019de7e5f704787ec5a11976d60f17f2935dcf60ea074ef0ca0d639b85c89478281f309f90d27774b68f7c7f47d283b6bb924d6ac4033f45d3a46d9603500a50febd7923e1aeccbae0daf8f7a9e2d7e20aae5250f5d4cc1487ddd38da375ac631fb97bbb4b65ebfa4b5d9ce7ceb2b4087dcf36eade6af5ca691a0b616c66ab75aded4681f337669f7f25b074f3aea3c0cc2763bd2c57bdfd453c32987cb5b37b7666cbce4390d6de93ebe1615a7200d8fc335bf84e576f585e6dd7df9584c90c0b68f8acd70380ee9e0182683f6dd8065fda1a31c58b16926c7a8f3176a11f0edd24b3780e7f898fa816988b00ac2097743d60a9027f315597ed33b745210d30203010001a350304e301d0603551d0e04160414e3541f2ae907a8e347fd50d9a28e5e0e64f2451f301f0603551d23041830168014e3541f2ae907a8e347fd50d9a28e5e0e64f2451f300c0603551d13040530030101ff300d06092a864886f70d010105050003820101002226306e672bacbe12cd65e96a2c4936f05a3e69dbd50cf384a29c8717537049f984c058074b43f38a47b7b287802b966917e02a8f37b6d6a99788905a684287c998264d9649d78c6bdc955de80b1e2d3b269776148bcdfabed6b15bd12a4afd564cc800fda7c6fbb776188f2b53ee2986bbf0e5476cc25dcaaf9ee90398edeb875081ff90515b0d3c386f28a70925d5ca2b47a73fdfd19ef0beee78befcdcfd8cf32db0b4f390202eab56b7e9b8097c480b67b73f1cad8efcc41b4657f29edda8f4920dc6f27928cf42ecec059399fb95ed3f201c6b4b0516b2a7fc9d6ae766970bacf2544d371f09b55eef0a47f15038eb956d3fb8d2cb9017d1d17b14af87""".toUpperCase()

    val bytes = Hex.decode(hex)

    val certHolder = new X509CertificateHolder(bytes)

    val cert = Engine.convert(certHolder)

    val text = cert.toString

    val dane = Engine.EntryFactory.createEntry(email, certHolder)

    val zoneLine = {
      val rdata = dane.getRDATA
      val repr = Hex.toHexString(dane.getRDATA).toUpperCase()
      s"${domain}. IN TYPE53 \\# ${rdata.length} ${repr}"
    }
  }

  // Simulate multiple available certs for the test email address by using 3 identical certs
  val testDaneEntries = Map(testEntry.domain -> Seq.fill(3)(testEntry.dane))

  /* DANE Entry Fetcher Factory that bypasses DNS and uses local entry table */
  class TestDaneEntryFetcherFactory extends DANEEntryFetcherFactory {
    override def build(domainName: String): DANEEntryFetcher = new DANEEntryFetcher {
      override def getEntries: util.List[_] = {
        import scala.collection.JavaConverters._
        testDaneEntries.getOrElse(domainName, Seq()).toList.asJava
      }
    }
  }

  /* DANE Entry Fetcher using the TestDANEEntryFetcherFactory */
  class TestDaneEntryFetcher extends DaneEntryFetcher(
    new TestDaneEntryFetcherFactory, Engine.TruncatingDigestCalculator)

  /* Engine that bypasses DNS and uses local entry table using TestDaneEntryFetcher */
  class TestEngine extends Engine {
    override val entryFetcher: DaneEntryFetcher = new TestDaneEntryFetcher
  }

  "An Engine" should "properly encode and decode PEM-format certificates" in {
    val decoded = Engine.fromPem(testEntry.pem)
    val encoded = Engine.toPem(decoded)
    assert(testEntry.certHolder.getEncoded.deep == decoded.getEncoded.deep)
    assert(testEntry.pem == encoded)
  }

  it should "properly Hex-encode and -decode DER-format certificates" in {
    val decoded = Engine.fromHex(testEntry.hex)
    val encoded = Engine.toHex(decoded)
    assert(testEntry.certHolder.getEncoded.deep == decoded.getEncoded.deep)
    assert(testEntry.hex == encoded)
  }

  it should "correctly fetch all certificates" in {
    val engine = new TestEngine
    val certs = engine.fetchCertificates(testEntry.email)
    assert(certs.length == 3)
    certs.foreach(cert => assert(cert == testEntry.cert))
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
    val certs = engine.text(testEntry.email)
    assert(certs.length == 3)
    certs.foreach(text => assert(text == testEntry.text))
  }

  it should "return all certificates in hex form" in {
    val engine = new TestEngine
    val certs = engine.hex(testEntry.email)
    assert(certs.length == 3)
    certs.foreach(hex => assert(hex == testEntry.hex))
  }

  it should "return all certificates in pem form" in {
    val engine = new TestEngine
    val certs = engine.pem(testEntry.email)
    assert(certs.length == 3)
    certs.foreach(pem => assert(pem == testEntry.pem))
  }

  it should "return valid DNS Zone Lines for each certificate" in {
    val engine = new TestEngine
    val lines = engine.dnsZoneLines(testEntry.email)
    assert(lines.length == 3)
    lines.foreach(line => assert(line == testEntry.zoneLine))
  }

  it should "create a valid DNS Zone Line" in {
    val engine = new TestEngine
    val linePem = engine.dnsZoneLine(testEntry.email, testEntry.pem)
    val lineDer = engine.dnsZoneLine(testEntry.email, testEntry.bytes)
    assert(linePem == testEntry.zoneLine)
    assert(lineDer == testEntry.zoneLine)
  }
}
