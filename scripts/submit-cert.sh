#!/usr/bin/env bash
if [ $# -ne 2 ]; then
    echo "Usage: $0 <pem-cert> <email-address>"
fi

curl -s -X POST --data-binary @"$1" http://localhost:25353/"$2"/dnsZoneLineForCert
