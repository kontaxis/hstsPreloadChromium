#!/bin/bash

# https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
URL="https://chromium.googlesource.com/chromium/src/net/+/master/http/transport_security_state_static.json?format=TEXT"

curl -L "${URL}" | base64 --decode |
	egrep -v "^([ ]*\/\/|$)" > "chromium_hsts_list.dat";
