#!/bin/bash

# https://blog.mozilla.org/security/2012/11/01/preloading-hsts/
URL="https://chromium.googlesource.com/chromium/src/net/+/refs/heads/main/http/transport_security_state_static.json?format=TEXT"

curl -L "${URL}" | base64 --decode |
	egrep -v "^([ ]*\/\/|$)" > "transport_security_state_static";
