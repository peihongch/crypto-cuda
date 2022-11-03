all: gaes_xts sha256

debug: gaes_xts-debug sha256-debug

gaes_xts: gaes_xts.cu
	nvcc gaes_xts.cu -L /usr/local/cuda/lib -lcudart -o gaes_xts

gaes_xts-debug: gaes_xts.cu
	nvcc -g -G gaes_xts.cu -L /usr/local/cuda/lib -lcudart -o gaes_xts-debug

sha256: sha256.cu
	nvcc sha256.cu -L /usr/local/cuda/lib -lcudart -o sha256

sha256-debug: sha256.cu
	nvcc -g -G sha256.cu -L /usr/local/cuda/lib -lcudart -o sha256-debug
