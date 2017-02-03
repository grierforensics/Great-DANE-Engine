# Great DANE Engine

An HTTP REST service for

1. Retrieving certificates for an email address via DNS, DNSSEC, DANE and SMIMEA, and
2. Generating DNS SMIMEA records for a given certificate

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

## Implementation

The HTTP REST service is implemented using Jersey and an embedded Jetty HTTP server.

## Build

The simplest way to build and run the Engine is to use the SBT `pack` target, provided
by the `sbt-pack` plugin. This builds a `bin/` and `lib/` directory containing
everything needed to run the service.

## Install

Create a cross-platform installer using `sbt izpack:create-installer`.
This generates the jar `target/installer.jar`, which will install the Great
DANE Engine on Windows, Linux or OS X. The service requires Apache Commons
Daemon `jsvc` on Linux or OS X. See `bin/greatdaneengine.sh` for details on how
to install `jsvc` on each platform.

## Configuration

The Engine can be configured using Java properties or any other method supported
by [Typesafe Config](https://github.com/typesafehub/config#standard-behavior).

- `com.grierforensics.greatdane.engine.port`: Local port on which to run HTTP REST service
- `com.grierforensics.greatdane.engine.dns`: List of DNS server addresses to use
    When specifying DNS servers on the command line, use the form `-Dcom.grierforensics.greatdane.engine.dns.0=X.X.X.X`

## Run

Run the `service` script found in `target/pack/bin/`.

## License

Dual-licensed under Apache License 2.0 and 3-Clause BSD License. See LICENSE.
