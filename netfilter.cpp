#include "netfilter.hpp"

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	fputc('\n', stdout);
	u_int32_t id = print_pkt(nfa);
	printf("\nentering callback\n");
	
	int ret;
	unsigned char *payload;
	ret = nfq_get_payload(nfa, &payload);
	if (ret >= 0){
		printf("payload_len=%d\n", ret);
	}

	Iphdr* ipheader = reinterpret_cast<Iphdr*>(payload);
	
	// check tcp
	if (ipheader->protocol != Iphdr::tcp)
		// ACCEPT
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	
	Tcphdr* tcpheader = reinterpret_cast<Tcphdr*>(payload + ipheader->offset());
	
	// check port
	if (tcpheader->dport() != 80 && tcpheader->sport() != 80)
		// ACCEPT
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	
	
	// check data exist
	if (ret <= (tcpheader->offset() + ipheader->offset()) )
		// ACCEPT
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	//printf("tcpdata_len=%d\n", (ret - tcpheader->offset() - ipheader->offset()) );

	string tcp_data = string(reinterpret_cast<char*>(payload + ipheader->offset() + tcpheader->offset()));

	// check http head (not body of packet)
	bool ishttp = false;
	vector<string> http_method = {"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};
	for (auto it = http_method.begin(); it != http_method.end(); it++)
	{
		if( strncmp(tcp_data.c_str(), (*it).c_str(), (*it).length()) == 0){
			ishttp = true;
			break;
		};
	}	
	if(ishttp == false) 
		// ACCEPT
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

	// find host
	size_t host_offset = tcp_data.find("Host");
	
	// if no host
	if (host_offset == string::npos)
		// ACCEPT
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	
	// substr host
	string host = tcp_data.substr(host_offset+6);
	host = host.substr(0, host.find("\r\n"));
	
	//cout << host << "\n";

	// host != argv[1]
	if (host != arg_host)
		// ACCEPT
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	
	// If debug ==true : dump memory
	if (debug)
		dump(payload, ret);
	
	printf("[!] DROP!\n");
	
	// DROP
	return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

/* returns packet id */
u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	return id;
}

void dump(unsigned char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02X ", buf[i]);
	}
	printf("\n");
}
