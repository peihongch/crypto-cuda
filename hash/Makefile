# all: shatest
all: sha1 sha224-256 sha384-512 hmac usha isha

# shatest: shatest.c sha1 sha224-256 sha384-512 hmac usha
# 	gcc -o shatest shatest.c sha1.o sha224-256.o sha384-512.o hmac.o usha.o

sha1: sha1.cu
	nvcc -g -G -O3 -rdc=true -Xcompiler -fPIC -c sha1.cu

sha224-256: sha224-256.cu
	nvcc -g -G -O3 -rdc=true -Xcompiler -fPIC -c sha224-256.cu

sha384-512: sha384-512.cu
	nvcc -g -G -O3 -rdc=true -Xcompiler -fPIC -c sha384-512.cu

usha: usha.cu
	nvcc -g -G -O3 -rdc=true -Xcompiler -fPIC -c usha.cu

isha: isha.cu
	nvcc -g -G -O3 -rdc=true -Xcompiler -fPIC -DISHA_TEST -c isha.cu

hmac: hmac.cu usha
	nvcc -g -G -O3 -rdc=true -Xcompiler -fPIC -c hmac.cu

clean: 
	rm -rf shatest *.o
