SUBDIRS = hash
DISTS = gaes_xts ghmac_sha gxts_hmac gaes_xts-debug ghmac_sha-debug gxts_hmac-debug

all: $(SUBDIRS)

debug: $(SUBDIRS) gaes_xts-debug ghmac_sha-debug

.PHONY: gaes_xts ghmac_sha gxts_hmac isha $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(TARGET)

gaes_xts: gaes_xts.cu
	nvcc gaes_xts.cu -L /usr/local/cuda/lib -lcudart -o gaes_xts

gaes_xts-debug: gaes_xts.cu
	nvcc -g -G gaes_xts.cu -L /usr/local/cuda/lib -lcudart -o gaes_xts-debug

ghmac_sha: ghmac_sha.cu hash
	nvcc -O3 -rdc=true -Xcompiler -fPIC ghmac_sha.cu hash/sha1.o hash/sha224-256.o hash/sha384-512.o hash/hmac.o hash/usha.o -L /usr/local/cuda/lib -lcudart -o ghmac_sha

ghmac_sha-debug: ghmac_sha.cu hash
	nvcc -g -G -O3 -rdc=true -Xcompiler -fPIC ghmac_sha.cu hash/sha1.o hash/sha224-256.o hash/sha384-512.o hash/hmac.o hash/usha.o -L /usr/local/cuda/lib -lcudart -o ghmac_sha-debug

gxts_hmac: gxts_hmac.cu hash
	nvcc -O3 -rdc=true -Xcompiler -fPIC gxts_hmac.cu hash/sha1.o hash/sha224-256.o hash/sha384-512.o hash/hmac.o hash/usha.o -L /usr/local/cuda/lib -lcudart -o gxts_hmac

gxts_hmac-debug: gxts_hmac.cu hash
	nvcc -g -G -O3 -rdc=true -Xcompiler -fPIC gxts_hmac.cu hash/sha1.o hash/sha224-256.o hash/sha384-512.o hash/hmac.o hash/usha.o -L /usr/local/cuda/lib -lcudart -o gxts_hmac-debug

isha: hash
	nvcc -O3 -rdc=true -Xcompiler -fPIC hash/sha1.o hash/sha224-256.o hash/sha384-512.o hash/hmac.o hash/usha.o hash/isha.o -L /usr/local/cuda/lib -lcudart -o isha

clean:
	$(MAKE) all kv=$(kv) TARGET=clean
	rm -rf $(DISTS)
