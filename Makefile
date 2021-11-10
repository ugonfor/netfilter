LDLIBS=-lnetfilter_queue

all: netfilter
	
netfilter: main.o netfilter.o netfilter.hpp iphdr.hpp
	g++   netfilter.o main.o  -lnetfilter_queue -o netfilter

clean:
	rm netfilter *.o