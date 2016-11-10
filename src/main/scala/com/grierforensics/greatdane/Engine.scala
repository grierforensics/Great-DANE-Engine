// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import java.security.Security
import java.security.cert.X509Certificate

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.dane._
import org.bouncycastle.cert.dane.fetcher.JndiDANEFetcherFactory
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.operator.bc.BcRSAContentVerifierProviderBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.operator.{DefaultDigestAlgorithmIdentifierFinder, DigestCalculator}
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
  import Engine._

  val fetcherFactory = new JndiDANEFetcherFactory()
  dnsServers.foreach(fetcherFactory.usingDNSServer(_))

  val entryFetcher = new DaneEntryFetcher(fetcherFactory, TruncatingDigestCalculator)

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
    fetchCertificates(emailAddress).map(_.toString)
  }

  /** Retrieves hex-encodings of DER-encoded certificates for the given email address
    *
    * @param emailAddress target email address
    * @return zero or more DER-encoded certificates (as hex strings)
    */
  def hex(emailAddress: String): Seq[String] = {
    fetchCertificates(emailAddress).map(toHex)
  }

  /** Retrieves PEM-encoded certificates for the given email address
    *
    * @param emailAddress target email address
    * @return zero or more PEM-encoded certificates
    */
  def pem(emailAddress: String): Seq[String] = {
    fetchCertificates(emailAddress).map(toPem)
  }

  /** Retrieves X.509 certificates for the given email address using DANE SMIMEA
    *
    * @param emailAddress target email address
    * @return zero or more X.509 certificates
    */
  def fetchCertificates(emailAddress: String): Seq[X509Certificate] = {
    fetchEntries(emailAddress: String).map(entry => convert(entry.getCertificate))
  }

  /** Creates sample DNS Zone lines for each DANE SMIMEA entry found in DNS
    *
    * @param emailAddress email address to resolve
    * @return Seq of sample DNS Zone lines
    */
  def dnsZoneLines(emailAddress: String): Seq[String] = {
    fetchEntries(emailAddress).map(formatDaneSmimeaDnsZoneLine(_))
  }

  /** Creates a new sample DNS Zone line for the given email address and PEM-encoded certificate
    *
    * @param emailAddress email address to associate
    * @param pemEncodedCertificate PEM-encoded certificate to add to DNS
    * @return sample DNS Zone line
    */
  def dnsZoneLine(emailAddress: String, pemEncodedCertificate: String): String = {
    val encoded = fromPem(pemEncodedCertificate)
    val entry = createEntry(emailAddress, encoded)
    formatDaneSmimeaDnsZoneLine(entry)
  }

  /** Creates a new sample DNS Zone line for the given email address and DER-encoded certificate
    *
    * @param emailAddress email address to associate
    * @param derEncodedCertificate DER-encoded certificate to add to DNS
    * @return sample DNS Zone line
    */
  def dnsZoneLine(emailAddress: String, derEncodedCertificate: Array[Byte]): String = {
    val entry = createEntry(emailAddress, derEncodedCertificate)
    formatDaneSmimeaDnsZoneLine(entry)
  }


  private def formatDaneSmimeaDnsZoneLine(entry: DANEEntry): String = {
    s"${entry.getDomainName}. IN TYPE${DaneType} \\# ${entry.getRDATA.length} ${toHex(entry.getRDATA)}"
  }

  private def createEntry(emailAddress: String, encodedCertificate: Array[Byte]): DANEEntry = {
    EntryFactory.createEntry(emailAddress, new X509CertificateHolder(encodedCertificate))
  }

  private def createEntry(emailAddress: String, certificate: X509Certificate): DANEEntry = {
    createEntry(emailAddress, certificate.getEncoded)
  }

  private def fetchEntries(emailAddress: String): Seq[DANEEntry] = {
    try {
      entryFetcher.fetch(emailAddress)
    } catch {
      case e: DANEException if e.getMessage.contains("DNS name not found") => Nil
    }
  }

}

object Engine {

  val DaneType = "53"

  // "Old" type used for temporary compatibility
  val OldDaneType = "65500"

  // Ensure the BouncyCastleProvider is installed only once
  private val Provider = new BouncyCastleProvider()
  Security.addProvider(Provider)

  private val CertificateConverter = new JcaX509CertificateConverter().setProvider(Provider)

  val TruncatingDigestCalculator = {
    // Sample usage: https://github.com/bcgit/bc-java/blob/master/pkix/src/test/java/org/bouncycastle/cert/test/DANETest.java
    val digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(Engine.Provider).build()
    val sha256DigestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))
    new TruncatingDigestCalculator(sha256DigestCalculator)
  }

  val Sha224DigestCalculator = {
    val digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(Engine.Provider).build()
    digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224))
  }

  val EntryFactory = new DANEEntryFactory(TruncatingDigestCalculator)

  class InvalidCertificateException(message: String) extends Exception(message)

  /** Fetches DANE Entries for a given email address
    *
    * Note that BC provides a DANECertificateFetcher, but in some cases we need
    * to retrieve the entire Entry, rather than just the certificate. This class
    * is nearly identical to DANECertificateFetcher.
    *
    * @param fetcherFactory fetcher to use for resolving requests
    * @param digestCalculator digest calculator for calculating subdomains
    */
  class DaneEntryFetcher(fetcherFactory: DANEEntryFetcherFactory, digestCalculator: DigestCalculator) {
    val selectorFactory = new DANEEntrySelectorFactory(digestCalculator)

    def fetch(emailAddress: String): Seq[DANEEntry] = {
      val selector = selectorFactory.createSelector(emailAddress)
      import scala.collection.JavaConverters._
      val matches = fetcherFactory.build(selector.getDomainName).getEntries.asScala
      matches.map(_.asInstanceOf[DANEEntry]).filter(selector.`match`(_))
    }
  }

  /** Converts an X509CertificateHolder to an X509Certificate */
  def convert(ch: X509CertificateHolder): X509Certificate = CertificateConverter.getCertificate(ch)

  /** Encodes X.509 Certificate data to PEM */
  def toPem(ch: X509CertificateHolder): String = toPem(convert(ch))
  def toPem(cert: X509Certificate): String = {
    import java.io.StringWriter

    import org.bouncycastle.openssl.jcajce.JcaPEMWriter

    val sw = new StringWriter()
    val pemWriter = new JcaPEMWriter(sw)
    try {
      pemWriter.writeObject(cert)
    } finally {
      pemWriter.close()
    }
    sw.toString
  }

  /** Decode a PEM-encoded certificate into an X.509 Certificate object */
  def fromPem(encoded: String): X509Certificate = {
    import java.io.StringReader

    val parser = new PEMParser(new StringReader(encoded))
    val obj = parser.readObject()

    obj match {
      case holder: X509CertificateHolder => CertificateConverter.getCertificate(holder)
        // TODO: support public keys, warn/error for private keys
        // See https://gist.github.com/akorobov/6910564 for examples
      case _ => throw new RuntimeException("Invalid PEM-encoded certificate.")
    }
  }

  /** Encodes X.509 Certificate data to DER as Hex-encoded string */
  def toHex(ch: X509CertificateHolder): String = toHex(convert(ch))
  def toHex(cert: X509Certificate): String = toHex(cert.getEncoded)
  def toHex(data: Array[Byte]): String = Hex.toHexString(data).toUpperCase

  // For symmetry/testing
  def fromHex(hex: String): X509Certificate = {
    val bytes = Hex.decode(hex)
    val holder = new X509CertificateHolder(bytes)
    CertificateConverter.getCertificate(holder)
  }


  /** Command-line tool for testing */
  def main(args: Array[String]): Unit = {
    val engine = new Engine()
    engine.fetchCertificates(args(0)).foreach(cert => println(cert.getSubjectDN))
  }
}
