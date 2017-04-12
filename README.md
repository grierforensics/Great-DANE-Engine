# Great DANE

Great DANE is a suite of tools designed to enable users to send secure, private emails without having to explicitly exchange public keys. By default, email is sent in the clear (without encryption) and unsigned (unauthenticated). S/MIME solves both of these problems by encrypting and signing emails, however it requires you to have the certificate belonging to your correspondent, presenting a chicken-and-egg problem. By using the DNS as a secure distributed database for S/MIME certificates, we can eliminate this barrier and finally make email completely confidential and authenticated.

For more information on DANE SMIMEA, please see the [IETF RFC](https://tools.ietf.org/html/draft-ietf-dane-smime-16).

# Great DANE Engine

The Great DANE Engine is the central component of Great DANE, encompassing DANE SMIMEA, DNS, DNSSEC, and S/MIME, and providing a simple REST API for effortless integration with any mail client.

The HTTP REST service provides the ability to

1. Retrieve S/MIME certificates for an email address via DNS, DNSSEC, DANE and SMIMEA, and
2. Generate an SMIMEA DNS record for a given S/MIME certificate

The Great DANE Engine can be installed locally or site-wide, giving users access to S/MIME certificates
for every email address having a corresponding SMIMEA record in DNS.

For getting started with your mail client, see the [Great DANE for Thunderbird](https://github.com/grierforensics/Great-DANE-Thunderbird) and [Great DANE for Horde Webmail](https://github.com/grierforensics/Great-DANE-Horde-Webmail) projects. The [Great DANE Toolset](https://github.com/grierforensics/Great-DANE-Toolset) is also a handy resource for testing DANE SMIMEA support and a great proof-of-concept.

## Install

The cross-platform Great DANE Engine installer can be found under [Releases](https://github.com/grierforensics/Great-DANE-Engine/releases).
On Windows, this will install and enable the Great DANE Engine as a Windows service (running on port 25353).
On OS X and Linux, you'll need the Apache Commons Daemon (`jsvc`), which is available through most packaging systems, including APT, yum, and Homebrew. Start the service using the `greatdaneengine.sh` script found in `<install-dir>/bin`.

Optionally, the Great DANE Engine can be built from source by following the [Build instructions](#build) below.

We also plan to host a public instance of the Great DANE Engine for experimental use in the near future.

## Configure

The Great DANE Engine can be configured via `conf/engine.conf` in the installation directory.

A sample configuration is shown below:

```
// DO NOT REMOVE (Include the default configuration)
include "application"

com.grierforensics.greatdane.engine {

  // REST server HTTP port
  port = 25353

  // DNS Server(s)
  dns = ["8.8.8.8", "8.8.4.4"]
}
```

If using the Great DANE Engine as a standalone JVM application, or integrating it into existing software, it can be configured using Java properties or any other method supported by [Typesafe Config](https://github.com/typesafehub/config#standard-behavior), for example:

```
$ sbt pack
$ JAVA_OPTS=-Dcom.grierforensics.greatdane.engine.dns.0="8.8.8.8" ./target/pack/bin/service
```

## API

1. `GET {email}/{format: pem|hex|text|dnsZoneLine}`

    Retrieves all certificates for the given email address.
    - `email`: email address to resolve
    - `format`: requested format of retrieved certificates
    - returns certificates in requested format or 404 if not found

2. `GET {email}/{format: pem|hex|text|dnsZoneLine}/{id}`

    Retrieves a certificate for the given email address.
    - `email`: email address to resolve
    - `format`: requested format of retrieved certificate
    - `id`: index of certificate requested
    - returns certificate in requested format or 404 if not found

3. `POST {email}/dnsZoneLineForCert`

    Creates a DANE Entry for the given email address and POSTed certificate.
    - email: email address to encode
    - POST body: certificate to use in DANE entry (encoded in PEM format)
    - returns the corresponding DNS zone line

## Build

The Great DANE Engine is implemented in Scala, using Jersey and an embedded Jetty HTTP server to provide the HTTP REST functionality.

To compile the service you'll need [SBT](http://www.scala-sbt.org/), the standard tool for building Scala projects.

Compile and test:

```
$ sbt compile
$ sbt test
```

Build the command-line tools/scripts (`bin/`, `lib/`)

```
$ sbt pack
$ ls ./target/pack/bin/
```

Create distributable archives (`.zip`, `.tar.gz`):

```
$ sbt pack-archive
```

Build a cross-platform installer:

```
$ sbt izpack:create-installer
$ ls ./target/installer.jar
```

## License

Dual-licensed under Apache License 2.0 and 3-Clause BSD License. See LICENSE.
