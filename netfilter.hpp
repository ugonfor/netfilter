#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>


#include <iostream>
#include <vector>
#include <string>
#include <string.h>
using namespace std;

extern bool debug;
extern bool quite;
extern string arg_host;

u_int32_t print_pkt (struct nfq_data *tb);
void dump(unsigned char* buf, int size);
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data);