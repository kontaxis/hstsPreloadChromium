#!/usr/bin/python -u

# kontaxis 2015-11-03

# Chromium maintains an HSTS preload list so that URLs for domains
# supporting HSTS are always automatically rewritten from HTTP to HTTPS
# (if necessary). This eliminates the vulnerability window the first time
# someone visits such domain over HTTP->HTTPS. Mozilla Firefox uses the
# same preload list to implement the same functionality.
#
# This program will take a hostname as input and print it in its output
# if the hostname is found on the HSTS preload list. Otherwise it will
# print nothing.

# References:
# - https://blog.mozilla.org/security/2012/11/01/preloading-hsts/

from __future__ import print_function

import argparse
import os
import sys
import sqlite3

class hstsPreloadChromium:
	verbose = False

	_dbConnCursor = None

	def __init__(self, dbPath):
		conn = sqlite3.connect(dbpath)
		conn.text_factory = str
		self._dbConnCursor = conn.cursor()

	def lookup(self, entries):
		hits = []

		for hostname in entries:
			self.verbose and print("hsts '%s' : " % hostname, end="")

			self._dbConnCursor.execute('SELECT domain from hsts where domain=?',
				(hostname,))
			match = self._dbConnCursor.fetchone()
			if match:
				hits.append(hostname)
				self.verbose and print("TRUE")
				continue

			# Lookup was a miss.
			self.verbose and print("FALSE")

			# Look for ever shorter wildcards.
			labels = hostname.strip(".").split(".")

			for i in range(1, len(labels)):
				hsts_wild = ".".join(["*"] + labels[i:len(labels)])

				self.verbose and print("hsts '%s' : " % hsts_wild, end="")

				self._dbConnCursor.execute('SELECT domain from hsts where domain=?',
					(hsts_wild,))
				match = self._dbConnCursor.fetchone()
				if match:
					hits.append(hostname)
					self.verbose and print("TRUE")
					break

				# Wildcard lookup was a miss.
				self.verbose and print("FALSE")

		return hits


if __name__ == "__main__":

	# Parse arguments.
	parser = argparse.ArgumentParser(
		description="Look up entries in the Chromium HSTS preload list.")

	parser.add_argument("--verbose", "-v",
		action="store_const", const=True, default=False,
		help = "Output information on the lookup process.")

	parser.add_argument("entries", metavar="E", nargs="+",
		help="Entry to look up.")

	args = parser.parse_args()

	# Make sure the SQLite3 database file exists in the same directory.
	dirname = os.path.dirname(sys.argv[0])
	dbpath  = os.path.join(dirname, "db.sqlite3")

	if not os.path.exists(dbpath):
		print("ERROR. Path '%s' is unavailable." % dbpath, file=sys.stderr)
		sys.exit(-1)

	if not os.path.isfile(dbpath):
		print("ERROR. Path '%s' is not a file."  % dbpath, file=sys.stderr)
		sys.exit(-1)

	hsts = hstsPreloadChromium(dbpath)
	hsts.verbose = args.verbose

	hits = hsts.lookup(args.entries)
	for hit in hits:
		print("%s" % hit)

	# Success
	if hits:
		sys.exit(0)

	# Failure
	sys.exit(1)
