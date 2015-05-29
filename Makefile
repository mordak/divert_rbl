build: 
	gcc -Wall -o divert-rbl divert-rbl.c

run: build
	sudo ./divert-rbl

