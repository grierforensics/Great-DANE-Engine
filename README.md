# Great DANE Engine

An HTTP REST service for

1. Retrieving certificates for an email address via DNS, DNSSEC, DANE and SMIMEA, and
2. Generating DNS SMIMEA records for a given certificate

## Bouncy Castle

The DANE package (`org.bouncycastle.cert.dane`) is currently vendored within the
Engine's source tree (`com.grierforensics.greatdane.bc`) to include recent changes
made in Bouncy Castle's master git branch. We plan to revert to using
`org.bouncycastle.cert.dane.*` upon the next release of Bouncy Castle.

## Implementation

The HTTP REST service is implemented using Jersey and an embedded Jetty HTTP server.

## Build

The simplest way to build and run the Engine is to use the SBT `pack` target, provided
by the great `sbt-pack` plugin. This builds a `bin/` and `lib/` directory containing
everything needed to run the service.

## Configuration

The Engine can be configured using Java properties or any other method supported
by [Typesafe Config](https://github.com/typesafehub/config#standard-behavior).

- `com.grierforensics.greatdane.engine.port`: Local port on which to run HTTP REST service
- `com.grierforensics.greatdane.engine.dns`: List of DNS server addresses to use
    When specifying DNS servers on the command line, use the form `-Dcom.grierforensics.greatdane.engine.dns.0=X.X.X.X`

## Run

Run the `service` script found in `target/pack/bin/`.
