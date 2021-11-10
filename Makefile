LDLIBS=-lnetfilter_queue

all: netfilter
	
netfilter: main.o netfilter.o netfilter.hpp header/iphdr.hpp header/tcphdr.hpp
	g++   netfilter.o main.o  -lnetfilter_queue -o netfilter

clean:
	rm netfilter *.o
