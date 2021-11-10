LDLIBS=-lnetfilter_queue

all: netfilter
	
netfilter: main.o netfilter.o netfilter.h

clean:
	rm netfilter *.o