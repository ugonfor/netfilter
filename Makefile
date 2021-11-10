all:
	gcc -o nfqnl_test main.cpp -lnetfilter_queue

clean:
	rm nfqnl_test