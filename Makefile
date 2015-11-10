.PHONY: all clean

all: db.sqlite3

chromium_hsts_list.dat:
	bash get_list.sh

db.sqlite3: chromium_hsts_list.dat
	python makedb.py

clean:
	rm -i chromium_hsts_list.dat db.sqlite3
