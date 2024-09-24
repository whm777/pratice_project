#include <stdio.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <arpa/inet.h>
#include <inttypes.h>  


#define DEBUG 0
#define enablesend 

//dpdk绑定的网口按照顺序来，从0开始
int global_portid = 0;

#define NUM_MBUFS 4096
#define BURST_SIZE 128


#ifdef enablesend
uint8_t global_smac[RTE_ETHER_ADDR_LEN];
uint8_t global_dmac[RTE_ETHER_ADDR_LEN];

uint16_t global_sport;
uint16_t global_dport;

uint32_t global_dip;
uint32_t global_sip;
 
#endif

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};


static int ustack_init_port(struct rte_mempool *mbuf_pool){
    //获取绑定的网口数量
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports == 0){
        rte_exit(EXIT_FAILURE, "no support eth found\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(global_portid, &dev_info);
    //printf("device name: %s\n", dev_info.device->name);


    const int num_rx_queues = 1;
#ifdef enablesend
    printf("************enablesend****************\n");
    const int num_tx_queues = 1;
#else
    const int num_tx_queues = 0;
#endif
    rte_eth_dev_configure(global_portid, num_rx_queues, num_tx_queues, &port_conf_default);

    if(rte_eth_rx_queue_setup(global_portid, 0, 128, rte_eth_dev_socket_id(global_portid), NULL, mbuf_pool) < 0){
        rte_exit(EXIT_FAILURE, "could not setup RX queue\n");
    }

    //dev_info.offloads = port_conf_default.rxmode.offloads;
    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads = port_conf_default.rxmode.offloads;
#ifdef enablesend
    if(rte_eth_tx_queue_setup(global_portid, 0, 512, rte_eth_dev_socket_id(global_portid), &txconf) < 0){
        rte_exit(EXIT_FAILURE, "could not setup TX queue\n");
    }
#endif
    if(rte_eth_dev_start(global_portid) < 0){
        rte_exit(EXIT_FAILURE, "could not start dev");
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

#ifdef enablesend

/*
参数：
    msg:组织完成后的数据包地址
    data:需要修改的数据包的内容
    len：需要修改的数据包长度
返回值：
    ret：
*/
static int ustack_encode_udp_pkt(uint8_t *msg, uint8_t *data, uint16_t total_len)
{
    if (!msg || !data || total_len == 0) { // 增加len的有效性检查
        return -1; // 参数校验失败
    }

    // 第一步：以太网头
    struct rte_ether_hdr *ethhdr = (struct rte_ether_hdr *)msg;
    rte_memcpy(ethhdr->d_addr.addr_bytes, global_dmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ethhdr->s_addr.addr_bytes, global_smac, RTE_ETHER_ADDR_LEN);
    ethhdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4); // 使用DPDK提供的转换函数

    // IP头
    struct rte_ipv4_hdr *iphdr = (struct rte_ipv4_hdr *)(ethhdr + 1);
    iphdr->version_ihl = 0x45;
    iphdr->type_of_service = 0;
    iphdr->total_length = rte_cpu_to_be_16(total_len - sizeof(struct rte_ether_hdr)); // 明确写出IP头部大小
    iphdr->packet_id = 0;
    iphdr->fragment_offset = 0;
    iphdr->time_to_live = 64;
    iphdr->next_proto_id = IPPROTO_UDP;
    iphdr->src_addr = global_sip;
    iphdr->dst_addr = global_dip;
    iphdr->hdr_checksum = 0; // 在计算校验和前将其设为0
    iphdr->hdr_checksum = rte_ipv4_cksum(iphdr);

    // UDP头
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
    udphdr->src_port = global_sport;
    udphdr->dst_port = global_dport;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr); // 正确计算UDP数据段的长度
    udphdr->dgram_len = rte_cpu_to_be_16(udplen);

    // 复制数据到UDP负载
    rte_memcpy((uint8_t*)(udphdr + 1), data, udplen); // 确保复制的数据长度正确

    udphdr->dgram_cksum = 0;
    udphdr->dgram_cksum = rte_ipv4_udptcp_cksum(iphdr, udphdr);

    // 移除不必要的打印
    // printf("ustack_encode_udp_pkt\n");
    print_global_info(iphdr, udphdr);
    // printf("end ustack_encode_udp_pkt\n");

    return 0;
}


static void handle_udp_packet(struct rte_udp_hdr *udphdr, struct rte_ether_hdr *ethhdr, struct rte_ipv4_hdr *iphdr, struct rte_mempool *mbuf_pool, uint8_t portid) {
    rte_memcpy(global_smac, ethhdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_memcpy(global_dmac, ethhdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

    rte_memcpy(&global_sip, &iphdr->dst_addr, sizeof(uint32_t));
    rte_memcpy(&global_dip, &iphdr->src_addr, sizeof(uint32_t));

    rte_memcpy(&global_sport, &udphdr->dst_port, sizeof(uint16_t));
    rte_memcpy(&global_dport, &udphdr->src_port, sizeof(uint16_t));

    print_global_info(iphdr, udphdr);

    uint16_t length = rte_be_to_cpu_16(udphdr->dgram_len);
    uint16_t total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + length;
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "could not alloc mbuf\n");
    }
    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *msg = rte_pktmbuf_mtod(mbuf, uint8_t *);

    ustack_encode_udp_pkt(msg, (uint8_t *)(udphdr+1), total_length);
    rte_eth_tx_burst(portid, 0, &mbuf, 1);

}
#endif

#if 0
static void handle_tcp_packet(struct rte_tcp_hdr *tcphdr, struct rte_ether_hdr *ethhdr, struct rte_ipv4_hdr *iphdr, struct rte_mempool *mbuf_pool, uint8_t portid) {
    rte_memcpy(global_smac, ethhdr->d_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_memcpy(global_dmac, ethhdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

    rte_memcpy(&global_sip, &iphdr->dst_addr, sizeof(uint32_t));
    rte_memcpy(&global_dip, &iphdr->src_addr, sizeof(uint32_t));

    rte_memcpy(&global_sport, &tcphdr->dst_port, sizeof(uint16_t));
    rte_memcpy(&global_dport, &tcphdr->src_port, sizeof(uint16_t));

    print_global_info(iphdr, tcphdr);

    uint16_t length = rte_be_to_cpu_16(udphdr->dgram_len);
    uint16_t total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + length;
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "could not alloc mbuf\n");
    }
    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *msg = rte_pktmbuf_mtod(mbuf, uint8_t *);

    ustack_encode_udp_pkt(msg, (uint8_t *)(udphdr+1), total_length);
    rte_eth_tx_burst(portid, 0, &mbuf, 1);

}

#endif

int main(int argc, char *argv[]) {
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "error with EAL init\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "could not create mbuf pool\n");
    }
    ustack_init_port(mbuf_pool);

    while (1) {
        struct rte_mbuf *mbufs[BURST_SIZE] = {0};
        uint16_t num_recvd = rte_eth_rx_burst(global_portid, 0, mbufs, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "error receiving from eth\n");
        }

        for (int i = 0; i < num_recvd; i++) {
            struct rte_ether_hdr *ethhdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
            if (ethhdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
            if (iphdr->next_proto_id == IPPROTO_UDP) {
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

#ifdef enablesend
                handle_udp_packet(udphdr, ethhdr, iphdr, mbuf_pool, global_portid);
#endif
                printf("recv UDP: %s\n", (char *)(udphdr + 1));
                printf("***************************************\n");
            }
            else if (iphdr->next_proto_id == IPPROTO_TCP) {
                //解析tcp报文
                struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);

                //handle_tcp_packet(tcphdr, ethhdr, iphdr, mbuf_pool, global_portid);
                printf("recv TCP: %s\n", (char *)(tcphdr + 1));
                printf("***************************************\n");
            }
            else{
                printf("recv other protocol\n");

            }
        }
    }

    return 0;
}
