#!/usr/bin/env python

import json
import urllib2
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('email')
parser.add_argument('certfile')

args = parser.parse_args()

req = urllib2.Request('http://localhost:25353/{}/dnsZoneLineForCert'.format(args.email))
req.add_header('Content-Type', 'application/json')

with open(args.certfile) as f:
    cert = f.read()

response = urllib2.urlopen(req, cert)
j = json.load(response)
print(j)
