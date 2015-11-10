#!/usr/bin/python -u

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

# Populate hsts records array
hsts = []

f = file(os.path.join(dirname, "chromium_hsts_list.dat"), "r")
j = json.loads(f.read())
f.close()

for entry in j["entries"]:
	if not "mode" in entry or entry["mode"] != "force-https":
		continue
	# We expect a name.
	if not "name" in entry:
		continue
	hsts.append((entry["name"],))
	if not "include_subdomains" in entry or entry["include_subdomains"] != True:
		continue
	hsts.append(("*.%s" % entry["name"],))

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
	c.execute("CREATE TABLE hsts (domain text);")
	c.execute("CREATE INDEX hsts_domain on hsts (domain);")

c.execute('DELETE FROM last_generated');
c.execute('INSERT INTO last_generated VALUES(?)',
	(str(int(time.time())),))

c.execute('DELETE FROM hsts');
c.executemany('INSERT INTO hsts VALUES (?)', hsts)

conn.commit()
conn.close()
