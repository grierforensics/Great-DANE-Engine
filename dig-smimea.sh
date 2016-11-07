#!/usr/bin/env bash

hashed=$(./target/pack/bin/email-converter $1)
dig +dnssec +noall +answer +multi $hashed -c IN -t TYPE53
#dig +noall +answer +multi $hashed -c IN -t TYPE53
