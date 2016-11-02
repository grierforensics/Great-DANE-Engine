// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import java.security.Security
import javax.naming.Context
import javax.naming.directory.{DirContext, InitialDirContext}

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.dane.{DANEEntry, DANEEntrySelectorFactory, TruncatingDigestCalculator}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder

/** Queries for DANE SMIMEA records */
object DnsCheck {

  def main(allArgs: Array[String]): Unit = {
    if (allArgs.length < 1) {
      println("Usage: dns-check [-old] [<dns-server>...] <name|email>")
      sys.exit(1)
    }

    val old = allArgs(0) == "-old"
    val args = if (old) allArgs.tail else allArgs
    val DaneType = if (old) "65500" else "53"

    val env = new java.util.Hashtable[String, String]()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory")

    // These are defaults and should not be needed!
    env.put(Context.AUTHORITATIVE, "false")
    env.put("com.example.jndi.dns.recursion", "true")
    env.put("com.example.jndi.dns.timeout.initial", "1000")
    env.put("com.example.jndi.dns.timeout.retries", "4")

    val dnsServers = args.init.map(s => "dns://" + s).mkString(" ")
    if (dnsServers.nonEmpty) {
      env.put(Context.PROVIDER_URL, dnsServers)
    }

    val ctx = new InitialDirContext(env)

    // If "name" is an email address, convert it using the old, SHA-224 algo (for now)
    val domainName = if (args.last.contains("@")) new EmailConverter(old).convert(args.last) else args.last
    val dc = ctx.lookup(domainName).asInstanceOf[DirContext]
    println(s"Lookup: ${dc.getNameInNamespace}")


    val attrs = ctx.getAttributes(domainName, Array(DaneType))
    val smimeAttr = attrs.get(DaneType)
    if (smimeAttr != null) {
      println("Found SMIMEA record")

      val data = smimeAttr.get().asInstanceOf[Array[Byte]]
      if (DANEEntry.isValidCertificate(data)) {
        val entry = new DANEEntry(domainName, data)
        println(s"Subject: ${entry.getCertificate.getSubject}")

        import java.io.StringWriter
        val sw = new StringWriter()
        val pemWriter = new JcaPEMWriter(sw)
        try {
          pemWriter.writeObject(entry.getCertificate)
        } finally {
          pemWriter.close()
        }
        println(sw.toString)
      } else {
        println("Payload is not a valid certificate")

      }
    }

    /*
    val bindings = ctx.listBindings(domainName)
    while (bindings.hasMore()) {
      val b = bindings.next()
      println(s"${b.getClassName}, ${b.toString}")
    }
    */
  }
}

class EmailConverter(oldHashAlgo: Boolean = false) {

  val digestCalculator = {
    val digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
      .setProvider(EmailConverter.Provider).build()
    if (oldHashAlgo) {
      digestCalculatorProvider.get(
        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha224))
    } else {
      val sha256DigestCalculator = digestCalculatorProvider.get(
        new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))
      new TruncatingDigestCalculator(sha256DigestCalculator)
    }
  }

  val selectorFactory = new DANEEntrySelectorFactory(digestCalculator)

  /** Converts an email address to DANE SMIMEA domain */
  def convert(emailAddress: String): String = selectorFactory.createSelector(emailAddress).getDomainName
}

object EmailConverter {
  // Ensure the BouncyCastleProvider is installed only once
  private val Provider = new BouncyCastleProvider()
  Security.addProvider(Provider)

  def main(args: Array[String]): Unit = {
    val usage = "Usage: email-converter [-old] <email address> [<email-address>...]"
    if (args.length < 0) {
      println(usage)
      sys.exit(1)
    }

    var old = false
    val emailAddresses = args.toList match {
      case "-old" :: tail =>
        old = true
        tail

      case ("-h"|"-help") :: tail =>
        println(usage)
        sys.exit(1)

      case emailAddresses => emailAddresses
    }

    val converter = new EmailConverter(old)
    emailAddresses.foreach(addr => println(converter.convert(addr)))
  }
}
