.PHONY: all clean

all: db.sqlite3

transport_security_state_static:
	bash get_list.sh

db.sqlite3: transport_security_state_static
	python3 makedb.py

clean:
	rm -i transport_security_state_static db.sqlite3
