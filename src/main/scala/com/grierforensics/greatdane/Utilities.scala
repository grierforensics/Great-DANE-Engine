// Copyright (C) 2016 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import java.nio.file.{Files, Paths}
import javax.naming.Context
import javax.naming.directory.{DirContext, InitialDirContext}

import org.bouncycastle.cert.dane.{DANEEntry, DANEEntrySelectorFactory, DANEException}
import org.bouncycastle.util.encoders.Hex

object GenDaneEntry {
  def main(args: Array[String]): Unit = {
    if (args.length < 2) {
      println("Usage: gen-dane-entry <email> <cert (DER)>")
      sys.exit(1)
    }

    val email = args(0)
    val der = Files.readAllBytes(Paths.get(args(1)))
    //val pem = new String(Files.readAllBytes(Paths.get(args(1))))

    val engine = new Engine()
    println(engine.dnsZoneLine(email, der))
  }
}

/** Queries for DANE SMIMEA records */
object DnsCheck {

  def main(allArgs: Array[String]): Unit = {
    if (allArgs.length < 1) {
      println("Usage: dns-check [-old] [<dns-server>...] <name|email>")
      sys.exit(1)
    }

    val old = allArgs(0) == "-old"
    val args = if (old) allArgs.tail else allArgs
    val DaneType = if (old) Engine.OldDaneType else Engine.DaneType

    // The following is a "rewrite" of the core functionality of BouncyCastle's
    // JndiDANEFetcherFactory class, which "accidentally" lists all bindings for
    // a given domain name by calling `ctx.listBindings(domainName)`, which is
    // explicitly rejected by many DNS servers. For Java DNS notes, see
    // https://docs.oracle.com/javase/8/docs/technotes/guides/jndi/jndi-dns.html
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
      println(s"Found ${smimeAttr.size()} SMIMEA records")

      for (idx <- 0 until smimeAttr.size()) {
        val data = smimeAttr.get(idx).asInstanceOf[Array[Byte]]
        if (!DANEEntry.isValidCertificate(data)) {
          println(s"#$idx is not a valid certificate")
        }
        try {
          val entry = new DANEEntry(domainName, data)
          println(s"Subject: ${entry.getCertificate.getSubject}")
          println(Engine.toPem(entry.getCertificate))
        } catch {
          case e: DANEException => println("Failed to create DANEEntry")
        }
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
  val digestCalculator =
    if (oldHashAlgo) Engine.Sha224DigestCalculator else Engine.TruncatingDigestCalculator

  val selectorFactory = new DANEEntrySelectorFactory(digestCalculator)

  /** Converts an email address to DANE SMIMEA domain */
  def convert(emailAddress: String): String = selectorFactory.createSelector(emailAddress).getDomainName
}

object EmailConverter {
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

object EncodeHex {
  def main(args: Array[String]): Unit = {
    if (args.length < 2) {
      println("Usage: encode-hex <infile> <outfile>")
      sys.exit(1)
    }

    val bytes = Files.readAllBytes(Paths.get(args(0)))
    Files.write(Paths.get(args(1)), Hex.encode(bytes))
  }
}

object DecodeHex {
  def main(args: Array[String]): Unit = {
    if (args.length < 2) {
      println("Usage: decode-hex <infile> <outfile>")
      sys.exit(1)
    }

    val bytes = Files.readAllBytes(Paths.get(args(0)))
    val s = new String(bytes, "utf-8").replaceAll("\\s", "")
    Files.write(Paths.get(args(1)), Hex.decode(s))
  }
}

