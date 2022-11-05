all: shatest

shatest: shatest.c sha1 sha224-256 sha384-512 hmac usha
	gcc -o shatest shatest.c sha1.o sha224-256.o sha384-512.o hmac.o usha.o

sha1: sha1.c
	gcc -c sha1.c

sha224-256: sha224-256.c
	gcc -c sha224-256.c

sha384-512: sha384-512.c
	gcc -c sha384-512.c

usha: usha.c
	gcc -c usha.c

hmac: hmac.c usha
	gcc -c hmac.c

clean: 
	rm -rf shatest *.o
