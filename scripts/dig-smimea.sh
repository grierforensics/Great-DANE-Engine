#!/usr/bin/env bash

hashed=$(./target/pack/bin/convert-email $1)
dig +dnssec +noall +answer +multi $hashed -c IN -t TYPE53
