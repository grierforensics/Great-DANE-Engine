// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import java.io.StringWriter
import java.security.Security
import java.security.cert.X509Certificate

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.dane.{DANECertificateFetcher, DANEEntryFactory, DANEException, TruncatingDigestCalculator}
import org.bouncycastle.cert.dane.fetcher.JndiDANEFetcherFactory
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.encoders.Hex

/** Core DANE SMIMEA Engine.
  *
  * Adds and retrieves DANE SMIMEA records to/from configured DNS server.
  *
  * NOTE: to add DNSSEC+validation, we would need to implement our own
  *       DANEFetcherFactory. See BouncyCastle's JndiDANEFetcherFactory
  *       (https://github.com/bcgit/bc-java/blob/master/pkix/src/main/java/org/bouncycastle/cert/dane/fetcher/JndiDANEFetcherFactory.java)
  *       and the dnsjava project.
  *
  * @param dnsServers DNS Server addresses
  */
class Engine(dnsServers: String*) {

  val truncatingDigestCalculator = {
    val digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
      .setProvider(Engine.Provider)
      .build()
    val sha256DigestCalculator = digestCalculatorProvider.get(
      new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))
    new TruncatingDigestCalculator(sha256DigestCalculator)
  }

  val sha224Digest = {
    val digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
      .setProvider(Engine.Provider)
      .build()
    digestCalculatorProvider.get(
      new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224))
  }

  val entryFactory = new DANEEntryFactory(truncatingDigestCalculator)

  val fetcher = {
    val fetcherFactory = new JndiDANEFetcherFactory()
    dnsServers.foreach(fetcherFactory.usingDNSServer(_))
    //new DANECertificateFetcher(fetcherFactory, truncatingDigestCalculator)
    new DANECertificateFetcher(fetcherFactory, sha224Digest)
  }

  val certConverter = new JcaX509CertificateConverter().setProvider(Engine.Provider)

  /* PLACEHOLDER for testing */
  val certdb = Map(
    "joe" -> List("hello", "world", "goodbye", "all")
  )
  def certs(email: String): List[String] = {
    certdb.getOrElse(email, List())
  }

  /** Retrieves plaintext certificates for the given email address
    *
    * @param emailAddress target email address
    * @return zero or more plaintext certificates
    */
  def text(emailAddress: String): Seq[String] = {
    fetchCerts(emailAddress).map(_.toString)
  }

  /** Retrieves hex-encodings of DER-encoded certificates for the given email address
    *
    * @param emailAddress target email address
    * @return zero or more DER-encoded certificates (as hex strings)
    */
  def hex(emailAddress: String): Seq[String] = {
    fetchCerts(emailAddress).map(cert => Hex.toHexString(cert.getEncoded).toUpperCase)
  }

  /** Retrieves PEM-encoded certificates for the given email address
    *
    * @param emailAddress target email address
    * @return zero or more PEM-encoded certificates
    */
  def pem(emailAddress: String): Seq[String] = {
    fetchCerts(emailAddress).map { cert =>
      val sw = new StringWriter()
      val pemWriter = new JcaPEMWriter(sw)
      try {
        pemWriter.writeObject(cert)
      } finally {
        pemWriter.close()
      }
      sw.toString
    }
  }

  /** Retrieves X.509 certificates for the given email address using DANE SMIMEA
    *
    * @param emailAddress target email address
    * @return zero or more X.509 certificates
    */
  def fetchCerts(emailAddress: String): Seq[X509Certificate] = {
    import scala.collection.JavaConverters._
    try {
      fetcher.fetch(emailAddress: String).asScala.map { obj =>
        val ch = obj.asInstanceOf[X509CertificateHolder]
        certConverter.getCertificate(ch)
      }
    } catch {
      case e: DANEException if e.getMessage.contains("DNS name not found") => Nil
    }
  }
}

object Engine {
  private val Provider = new BouncyCastleProvider()
  // Ensure the BouncyCastleProvider is installed only once
  Security.addProvider(Provider)

  def main(args: Array[String]): Unit = {
    val engine = new Engine()

    import scala.collection.JavaConverters._
    engine.fetcher.fetch(args(0)).asScala.foreach { o =>
      val ch = o.asInstanceOf[X509CertificateHolder]
      println(ch.getSubject)
    }
  }
}
