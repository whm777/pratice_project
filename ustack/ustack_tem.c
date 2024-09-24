

#include <stdio.h>

#include <rte_eal.h>
#include <rte_ethdev.h>

#include <arpa/inet.h>

int global_portid = 0;


#define NUM_MBUFS  4096
#define BURST_SIZE	128


#define ENABLE_SEND		1
#define ENABLE_TCP		1

#define TCP_INIT_WINDOWS		14600


#if ENABLE_SEND


uint8_t global_smac[RTE_ETHER_ADDR_LEN];
uint8_t global_dmac[RTE_ETHER_ADDR_LEN];


uint32_t global_sip;
uint32_t global_dip;

uint16_t global_sport;
uint16_t global_dport;


#endif

#if ENABLE_TCP

uint8_t global_flags;
uint32_t global_seqnum;
uint32_t global_acknum;


typedef enum __USTACK_TCP_STATUS {

	USTACK_TCP_STATUS_CLOSED = 0,
	USTACK_TCP_STATUS_LISTEN,
	USTACK_TCP_STATUS_SYN_RCVD,
	USTACK_TCP_STATUS_SYN_SENT,
	USTACK_TCP_STATUS_ESTABLISHED,
	USTACK_TCP_STATUS_FIN_WAIT_1,
	USTACK_TCP_STATUS_FIN_WAIT_2,
	USTACK_TCP_STATUS_CLOSING,
	USTACK_TCP_STATUS_TIMEWAIT,
	USTACK_TCP_STATUS_CLOSE_WAIT,
	USTACK_TCP_STATUS_LAST_ACK
	
} USTACK_TCP_STATUS;

uint8_t tcp_status = USTACK_TCP_STATUS_LISTEN;


#endif


static const struct rte_eth_conf port_conf_default = {
	.rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static int ustack_init_port(struct rte_mempool *mbuf_pool) {
//number
	uint16_t nb_sys_ports = rte_eth_dev_count_avail();
	if (nb_sys_ports == 0) {
		rte_exit(EXIT_FAILURE, "No Supported eth found\n");
	}

	struct rte_eth_dev_info dev_info;
	rte_eth_dev_info_get(global_portid, &dev_info);
// eth0, 

	const int num_rx_queues = 1;
#if ENABLE_SEND
	const int num_tx_queues = 1;
#else
	const int num_tx_queues = 0;
#endif
	rte_eth_dev_configure(global_portid, num_rx_queues, num_tx_queues, &port_conf_default);

	if (rte_eth_rx_queue_setup(global_portid, 0, 128, rte_eth_dev_socket_id(global_portid), NULL, mbuf_pool) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
	}

#if ENABLE_SEND

	struct rte_eth_txconf txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf_default.rxmode.offloads;
	if (rte_eth_tx_queue_setup(global_portid, 0, 512, rte_eth_dev_socket_id(global_portid), &txq_conf) < 0) {
		rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
	}
	
#endif 
	
	if (rte_eth_dev_start(global_portid) < 0) {
		rte_exit(EXIT_FAILURE, "Could not start\n");
	}

	return 0;
}

static void print_global_info(struct rte_ipv4_hdr *iphdr, struct rte_udp_hdr *udphdr) {
    struct in_addr addr;
    addr.s_addr = iphdr->src_addr;
    printf("src ip: %s : %d\n", inet_ntoa(addr),ntohs(udphdr->src_port));
    //printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", global_smac[0], global_smac[1], global_smac[2], global_smac[3], global_smac[4], global_smac[5]);
    addr.s_addr = iphdr->dst_addr;
    printf("dst ip: %s : %d\n", inet_ntoa(addr), ntohs(udphdr->dst_port));
    //printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", global_dmac[0], global_dmac[1], global_dmac[2], global_dmac[3], global_dmac[4], global_dmac[5]);
}

// msg
static int ustack_encode_udp_pkt(uint8_t *msg, uint8_t *data, uint16_t total_len) {

	//1 ether header

	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->d_addr.addr_bytes, global_dmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->s_addr.addr_bytes, global_smac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	//1 ip header
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr*)(eth + 1); //msg + sizeof(struct rte_ether_hdr);
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_UDP;
	ip->src_addr = global_sip;
	ip->dst_addr = global_dip;

	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	//1 udp header

	struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
	udp->src_port = global_sport;
	udp->dst_port = global_dport;
	uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
	udp->dgram_len = htons(udplen);

	rte_memcpy((uint8_t*)(udp+1), data, udplen);
	udp->dgram_cksum = 0;
	udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

	print_global_info(ip, udp);
	
	return 0;
}



// msg
static int ustack_encode_tcp_pkt(uint8_t *msg, uint16_t total_len) {

	//1 ether header

	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->d_addr.addr_bytes, global_dmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->s_addr.addr_bytes, global_smac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	//1 ip header
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr*)(eth + 1); //msg + sizeof(struct rte_ether_hdr);
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64;
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = global_sip;
	ip->dst_addr = global_dip;

	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	//1 tcp header

	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
	tcp->src_port = global_sport;
	tcp->dst_port = global_dport;
	tcp->sent_seq = htonl(12345);
	tcp->recv_ack = htonl(global_seqnum + 1);
	tcp->data_off = 0x50;
	tcp->tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG; //0x1 << 1;
	
	tcp->rx_win = TCP_INIT_WINDOWS; //htons(4096);  // rmem
	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
	

	
	return 0;
}




int main(int argc, char *argv[]) {

	if (rte_eal_init(argc, argv) < 0) {
		rte_exit(EXIT_FAILURE, "Error with EAL init\n");
	}

	struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (mbuf_pool == NULL) {
		rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
	}

	ustack_init_port(mbuf_pool);

	while (1) {

		struct rte_mbuf *mbufs[BURST_SIZE] = {0};

		uint16_t num_recvd = rte_eth_rx_burst(global_portid, 0, mbufs, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		}


		int i = 0;
		for (i = 0;i < num_recvd;i ++) {

			struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
			if (ethhdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
				continue;
			}

			struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
			if (iphdr->next_proto_id == IPPROTO_UDP) {

				struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
#if ENABLE_SEND

				rte_memcpy(global_smac, ethhdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				rte_memcpy(global_dmac, ethhdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

				rte_memcpy(&global_sip, &iphdr->dst_addr, sizeof(uint32_t));
				rte_memcpy(&global_dip, &iphdr->src_addr, sizeof(uint32_t));

				rte_memcpy(&global_sport, &udphdr->dst_port, sizeof(uint16_t));
				rte_memcpy(&global_dport, &udphdr->src_port, sizeof(uint16_t));

				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("sip %s:%d --> ", inet_ntoa(addr), ntohs(udphdr->src_port));

				addr.s_addr = iphdr->dst_addr;
				printf("dip %s:%d --> ", inet_ntoa(addr), ntohs(udphdr->dst_port));

				uint16_t length = ntohs(udphdr->dgram_len);
				uint16_t total_len = length + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr);

				struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
				if (!mbuf) {
					rte_exit(EXIT_FAILURE, "Error rte_pktmbuf_alloc\n");
				}
				mbuf->pkt_len = total_len;
				mbuf->data_len = total_len;

				uint8_t *msg = rte_pktmbuf_mtod(mbuf, uint8_t *);

				ustack_encode_udp_pkt(msg, (uint8_t*)(udphdr+1), total_len);

				rte_eth_tx_burst(global_portid, 0, &mbuf, 1);
#endif
				printf("udp : %s\n", (char*)(udphdr+1));

			} 
			//tcp三次握手，四次挥手都要分别处理
			else if (iphdr->next_proto_id == IPPROTO_TCP) {

				struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);

				rte_memcpy(global_smac, ethhdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
				rte_memcpy(global_dmac, ethhdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

				rte_memcpy(&global_sip, &iphdr->dst_addr, sizeof(uint32_t));
				rte_memcpy(&global_dip, &iphdr->src_addr, sizeof(uint32_t));

				rte_memcpy(&global_sport, &tcphdr->dst_port, sizeof(uint16_t));
				rte_memcpy(&global_dport, &tcphdr->src_port, sizeof(uint16_t));

				global_flags = tcphdr->tcp_flags;
				global_seqnum = ntohl(tcphdr->sent_seq);
				global_acknum = ntohl(tcphdr->recv_ack);

				struct in_addr addr;
				addr.s_addr = iphdr->src_addr;
				printf("tcp pkt sip %s:%d --> ", inet_ntoa(addr), ntohs(tcphdr->src_port));

				addr.s_addr = iphdr->dst_addr;
				printf("dip %s:%d , flags: %x, seqnum: %d, acknum: %d\n", inet_ntoa(addr), ntohs(tcphdr->dst_port), 
					global_flags, global_seqnum, global_acknum);

				if (global_flags & RTE_TCP_SYN_FLAG) {

					if (tcp_status == USTACK_TCP_STATUS_LISTEN) {
						uint16_t total_len = sizeof(struct rte_tcp_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_ether_hdr);

						struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
						if (!mbuf) {
							rte_exit(EXIT_FAILURE, "Error rte_pktmbuf_alloc\n");
						}
						mbuf->pkt_len = total_len;
						mbuf->data_len = total_len;

						uint8_t *msg = rte_pktmbuf_mtod(mbuf, uint8_t *);

						ustack_encode_tcp_pkt(msg, total_len);

						rte_eth_tx_burst(global_portid, 0, &mbuf, 1);

						tcp_status = USTACK_TCP_STATUS_SYN_RCVD;
					}

				}
				if (global_flags & RTE_TCP_ACK_FLAG) {


					if (tcp_status == USTACK_TCP_STATUS_SYN_RCVD) {

						printf("enter established\n");
						tcp_status = USTACK_TCP_STATUS_ESTABLISHED;
					}

				}
				if (global_flags & RTE_TCP_PSH_FLAG) {

					printf("enter established: %d\n", tcp_status);
					if (tcp_status == USTACK_TCP_STATUS_ESTABLISHED) {

						uint8_t hdrlen = (tcphdr->data_off >> 4) * sizeof(uint32_t);

						uint8_t *data = ((uint8_t*)tcphdr + hdrlen);

						printf("tcp data: %s\n", data);
					}

				}

			}

		}
		
		

	}


	printf("hello dpdk\n");

}




