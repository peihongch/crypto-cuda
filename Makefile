SUBDIRS = hash

all: $(SUBDIRS)

debug: $(SUBDIRS) gaes_xts-debug ghmac_sha-debug

.PHONY: gaes_xts ghmac_sha $(SUBDIRS)

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

clean:
	$(MAKE) all kv=$(kv) TARGET=clean
