#!/usr/bin/python3 -u

# kontaxis 2015-11-03

# References:
# - https://blog.mozilla.org/security/2012/11/01/preloading-hsts/

from __future__ import print_function

import json
import os
import sqlite3
import sys
import time

dirname = os.path.dirname(sys.argv[0])

# Populate entries array
entries = []

f = open(os.path.join(dirname, "transport_security_state_static"), "r")
j = json.loads(f.read())
f.close()

for entry in j["entries"]:
	# We expect a name.
	if not "name" in entry:
		continue
	mode = ""
	if "mode" in entry:
		mode = entry["mode"]
	entries.append((entry["name"],mode))
	if not "include_subdomains" in entry or entry["include_subdomains"] != True:
		continue
	entries.append(("*.%s" % entry["name"],mode))

# Make it happen
conn = sqlite3.connect("db.sqlite3")
conn.text_factory = str
c = conn.cursor()

# Create schema.
c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",
	("last_generated",))
match = c.fetchone()
if not match:
	c.execute("CREATE TABLE last_generated (epoch integer);")
	c.execute("CREATE TABLE entries (name text, mode text);")
	c.execute("CREATE INDEX name on entries (name);")

c.execute('DELETE FROM last_generated');
c.execute('INSERT INTO last_generated VALUES(?)',
	(str(int(time.time())),))

c.execute('DELETE FROM entries');
c.executemany('INSERT INTO entries VALUES (?,?)', entries)

conn.commit()
conn.close()
