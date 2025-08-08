appname := TeamSpeakHasher

NVCC := nvcc
NVCCFLAGS := -std=c++11

srcfiles = cuda_main.cu

all: $(appname)

$(appname): $(srcfiles)
	$(NVCC) $(NVCCFLAGS) -o $(appname) $(srcfiles)

clean:
	rm -f $(appname)
