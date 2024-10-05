#include <stdio.h>
#include <rte_eal.h>  
#include <rte_lcore.h>  
#include <rte_launch.h>  

#define ENABLE_SEND 1   //开启发送功能
#define ENABLE_PROMISCUOUS_MODE 1   //开启网卡混杂模式
#define ENABLE_RINGBUFFER 1
#define BURST_SIZE 32
#define LOCALADDR ""

#define LL_ADD(item, list) do { \
    item->prev = NULL;          \
    item->next = list;          \
    if(list != NULL) list->prev = item; \
    list = item;                \
}while(0)   

#define LL_REMOVE(item , list) do{   \
    if(item->prev != NULL) item->prev->next = item->next; \
    if(item->next != NULL) item->next->prev = item->prev; \
    if(list == item) list = item->next; \
    item->prev = item->next = NULL;     \
}while(0)

const static uint16_t nb_desc = 1024;
static struct rte_kni *global_kni;
struct rte_ether_addr * gSrcMac;
int gDpdkPortId = 0;    //这里因为环境只设置了一个网口，所以id是0


typedef enum _NG_TCP_STATUS{
    NG_TCP_STATUS_CLOSED = 0,
	NG_TCP_STATUS_LISTEN,
	NG_TCP_STATUS_SYN_RCVD,
	NG_TCP_STATUS_SYN_SENT,
	NG_TCP_STATUS_ESTABLISHED,

	NG_TCP_STATUS_FIN_WAIT_1,
	NG_TCP_STATUS_FIN_WAIT_2,
	NG_TCP_STATUS_CLOSING,
	NG_TCP_STATUS_TIME_WAIT,

	NG_TCP_STATUS_CLOSE_WAIT,
	NG_TCP_STATUS_LAST_ACK
}NG_TCP_STATUS;


struct ng_tcp_stream {
    int fd;

    uint32_t dip;
    uint32_t sip;
    uint8_t localmac[RTE_ETHER_ADD_LEN];
    uint16_t dport;
    uint16_t sport;

    uint8_t protocol;

    uint32_t snd_nxt;   //数据段的序列号，每发送一个，会递增相应的长度值，这也是为什么tcp不需要包长的原因
    uint32_t rcv_nxt;

    NG_TCP_STATUS status;

    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;

    struct ng_tcp_stream *prev;
    struct ng_tcp_stream *next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;

};

struct ng_tcp_table{
    struct ng_tcp_stream * tcp_set;
    int count;
};

struct ng_tcp_fragment {
    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t hdrlen_off;
    uint8_t flags;
    uint16_t windows;
    uint16_t checksum;
    uint16_t urgptr;    //紧急数据

    int optlen;
    uint32_t option[TCP_OPTION_LENGTH]; //可选控制信息

    unsigned char * data;
    uint32_t length;

};

struct arp_entry {
    uint32_t ip;
    uint8_t hwaddr[RTE_ETHER_ADDR_LEN];
    uint8_t type;       //TODO:这个做什么的

    struct arp_entry *next;
    struct arp_entry *prev;
}; 

struct arp_table {
    struct arp_entry *entries;
    int count;

    pthread_spinlock_t spinlock;    //自旋锁
};

struct localhost {
    int fd;
    uint32_t localip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;

    uint8_t protocol;

    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;

    struct localhost *prev;
    struct localhost *next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;  //TODO:为什么这里用互斥锁，而apr用自旋锁?
}

struct offload{
    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    int protocol;

    unsigned char * data;
    uint16_t length;
};

static struct localhost * lhost = NULL;


static const struct rte_eth_conf port_conf_default = {
    .rmmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static struct inout_ring* rInst = NULL;
static struct arp_table *arptab = NULL;
static struct ng_tcp_table * tInst = NULL;

static struct localhost *get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto){
    struct localhost * host = NULL;
    for(host= lhost; host != NULL; host = host->next){
        if(dip == host->localip && port == host->localport && proto == host->protocol){
            return host;
        }
    }
    return NULL;
}

static struct ng_tcp_table * tcpInstance(){
    if(tInst == NULL){
        tInst = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
        memset(rInst, 0 ,sizeof(struct ng_tcp_table));
    }
    return tInst;
}

/*
遍历TCP表的第一个链表，寻找完全匹配的五元组（源IP、目的IP、源端口、目的端口）的连接。
若未找到，则遍历同一个链表，寻找目的端口相同且状态为监听（NG_TCP_STATUS_LISTEN）的连接。*/
static struct ng_tcp_stream * ng_tcp_stream_seach(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport){
    struct ng_tcp_table * table = tcpInstance();
    struct ng_tcp_stream *iter;

    for(iter = table->tcb_set; iter != NULL; iter = iter->next){
        if(iter->sip == sip && iter->dip == dip && iter->sport == sport && iter->dport == dport){
            return iter;
        }
    }

    for(iter = table->tcb_set; iter != NULL; iter = iter->next){
        if(iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN ){
            return iter;
        }
    }
    return NULL;

}


/**
 * 创建TCP流对象
 * 
 * @param sip 源IP地址
 * @param dip 目的IP地址
 * @param sport 源端口号
 * @param dport 目的端口号
 * 
 * @return 新创建的TCP流对象指针，如果创建失败则返回NULL
 * 
 * 此函数负责根据给定的IP地址和端口号创建一个TCP流对象，并初始化其成员变量
 * 它为每个TCP连接创建一个单独的发送和接收环形队列，以避免冲突
 */
static struct ng_tcp_stream * ng_tcp_stream_create (uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport){
    // 分配内存并创建TCP流对象
    struct ng_tcp_stream * stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
    if(stream == NULL) return NULL;

    // 初始化TCP流对象的基本信息
    stream->sip = sip;
    stream->dip = dip;
    stream->sport = sport;
    stream->dport = dport;

    stream->protocol = IPPROTO_TCP;
    stream->fd = -1;

    // 设置TCP流的状态为监听状态
    stream->status = NG_TCP_STATUS_LISTEN;

    // 打印创建的TCP流对象的地址
    printf("[TCP] Create stream %p\n", stream);

    // 创建发送环形队列
    char sbufname[32] = 0;
    snprintf(sbufname, 32, "sndbuf%x%d", sip, sport);
    stream->sndbuf = ng_ring_create(sbufname, RING_SIZE , rte_socket_id(), 0);

    // 创建接收环形队列
    char rbufname[32] = 0;
    snprintf(rbufname, 32, "rcvbuf%x%d", dip, dport);
    stream->rcvbuf = ng_ring_create(rbufname, RING_SIZE , rte_socket_id(), 0);

    // 初始化TCP序列号
    uint32_t next_seed = time(NULL);
    stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;

    // 复制本地MAC地址
    rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    // 初始化条件变量
    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

    // 初始化互斥锁
    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    // 返回创建的TCP流对象指针
    return stream;
}

/**
 * ng_tcp_enqueue_recvbuffer 是一个用于TCP接收缓冲区入队列函数
 * 它负责将接收到的TCP数据段解析并添加到接收缓冲区队列中
 * 
 * @param stream 指向TCP流结构体的指针，表示当前的TCP连接流
 * @param tcphdr 指向TCP头部的指针，用于解析TCP数据段的头部信息
 * @param tcplen 表示TCP数据段的总长度，包括头部和有效载荷
 * 
 * @return 返回0表示成功，-1表示失败（如内存分配失败）
 */
static int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream * stream, struct rte_tcp_hdr * tcphdr, int tcplen){
    // 分配内存用于存储接收到的TCP片段
    struct ng_tcp_fragment * rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
    if(rfragment == NULL) return -1;
    memset(rfragment , 0 , sizeof(struct ng_tcp_fragment));

    // 解析并存储TCP头部的端口号信息
    rfragment->dport = ntohs(tcphdr->dst_port);
    rfragment->sport = ntohs(tcphdr->src_port);

    // 计算TCP头部长度，data_off字段的单位是32位字，需要右移4位得到字节数
    uint8_t hdrlen = tcphdr->data_off >> 4;
    // 计算有效载荷长度，即TCP数据段中除去头部的部分
    int payloadlen = tcplen - hdrlen * 4;
    if(payloadlen > 0){
        // 当有效载荷长度大于0时，分配内存用于存储有效载荷
        uint8_t * payload = (uint8_t *)tcphdr + hdrlen * 4;

        rfragment->data = rte_malloc("unsigned_char *", payloadlen + 1, 0);
        if(rfragment->data == NULL){
            rte_free(rfragment);
            return -1;
        }
        memset(rfragment->data, 0, payloadlen + 1);
        // 将有效载荷内容复制到分配的内存中
        rte_memcpy(rfragment->data, payload, payloadlen);
        rfragment->length = payloadlen;
    } else if(payloadlen == 0){
        // 当有效载荷长度为0时，设置data为NULL，length为0
        rfragment->data = NULL;
        rfragment->length = 0;
    }

    // 将解析后的TCP片段入队列到接收缓冲区队列中
    rte_ring_mp_enqueue(stream->rcvbuf, rfragment);

    // 加锁并触发条件变量，通知有新的数据到达
    pthread_mutex_lock(&stream->mutex);
    pthread_cond_signal(&stream->cond);
    pthread_mutex_unlock(&stream->mutex);
    
    return 0;
}

static int ng_tcp_send_ackpkt(struct ng_tcp_stream * stream , struct rte_tcp_hdr * tcphdr){
    struct ng_tcp_fragment * ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment));
    if(ackfrag == NULL) return -1;
    memset(ackfrag, 0 , sizeof(struct ng_tcp_fragment));

    ackfrag->dport = tcphdr->src_port;
    ackfrag->sport = tcphdr->dst_port;

    ackfrag->acknum = stream->rcv_nxt;
    ackfrag->seqnum = stream->snd_nxt;

    ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
    ackfrag->window = stream->snd_wnd;
    ackfrag->hdrlen_off = 0x50;
    ackfrag->data  = NULL;
    ackfrag->length = 0;

    rte_ring_mp_enqueue(stream->sndbuf, ackfrag);
    return 0;
}

/**
 * 处理监听状态下的TCP连接请求
 * 
 * 当TCP连接处于监听状态时，此函数会处理来自客户端的连接请求
 * 主要功能包括创建新的TCP流对象、分配内存、设置TCP头部信息，
 * 并将新连接添加到TCP流管理结构中
 * 
 * @param stream 指向本地TCP流的指针
 * @param tcphdr 指向TCP头部的指针
 * @param iphdr 指向IP头部的指针
 * @return 返回-1表示内存分配失败，否则无返回值
 */
static int ng_tcp_handle_listen(struct ng_tcp_stream * stream, struct rte_tcp_hdr * tcphdr, struct rte_ipv4_hdr * iphdr){
    // 检查TCP标志位，如果设置了SYN标志位，则表示这是一个新的连接请求
    if(tcphdr->tcp_flags & RTE_TCP_SYN_FLAG){
        // 如果当前流的状态是监听状态，则表示可以接受新的连接请求
        if(stream->status == NG_TCP_STATUS_LISTEN){
            // 获取TCP流管理实例
            struct ng_tcp_table * table = tcpInstance();
            // 创建新的TCP流对象，用于管理这个新的连接请求
            struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
            // 将新的TCP流对象添加到TCP流管理结构中
            LL_ADD(syn, table->tcb_set);

            // 分配内存用于存储TCP片段信息
            struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
            if(fragment == NULL) return -1; // 如果内存分配失败，返回-1
            memset(fragment, 0, sizeof(struct ng_tcp_fragment)); // 初始化内存

            // 设置TCP头部信息
            fragment->sport = tcphdr->dst_port;
            fragment->dport = tcphdr->src_port;
            fragment->seqnum = syn->snd_nxt;
            fragment->acknum = htohl(tcphdr->sent_seq) + 1;
            syn->rcv_nxt = fragment->acknum;

            // 设置TCP标志位为SYN+ACK，表示已经接收到SYN并准备发送ACK
            fragment->tcp_flags = (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG);
            fragment->window = TCP_INITIAL_WINDOW;
            fragment->hdrlen_off = 0x50;

            // 设置TCP片段数据
            fragment->data = NULL;
            fragment->length = 0;

            // 将TCP片段加入到发送缓冲区，并更新流的状态
            rte_ring_mp_enqueue(syn->sndbuf, fragment);
            syn->status = NG_TCP_STATUS_SYN_RCVD;
        }
    }

    return 0;
}

/**
 * 处理TCP连接中的SYN_RCVD状态
 * 当TCP头部的标志位包含ACK标志时，检查TCP连接的状态是否为SYN_RCVD，
 * 如果是，则更新连接的状态为ESTABLISHED，并进行必要的ACK序列号检查
 * 此外，通过查找监听套接字来处理连接的接受，并使用条件变量通知等待的线程
 *
 * @param stream 指向TCP流状态的指针
 * @param tcphdr 指向TCP头部的指针
 * @return 返回整型值，可能根据处理结果返回特定的错误码或状态码
 */
static int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream * stream, struct rte_tcp_hdr * tcphdr){
    // 检查TCP头部的标志位是否包含ACK标志
    if(tcphdr->flags & RTE_TCP_ACK_FLAG){
        // 验证TCP连接的状态是否为SYN_RCVD
        if(stream->status == NG_TCP_STATUS_SYN_RCVD){
            // 检查接收到的ACK序列号是否正确
            uint32_t acknum = ntohl(tcphdr->recv_ack);
            if(acknum == stream->snd_nxt + 1){
                //TODO: 确认接收到的ACK序列号正确后，此处可能需要处理连接的建立过程
            }

            // 更新TCP连接的状态为ESTABLISHED
            stream->status = NG_TCP_STATUS_ESTABLISHED;

            // 通过查找监听套接字来处理连接的接受
            struct ng_tcp_stream  * listener = ng_tcp_stream_seach(0 ,0 ,0, stream->dport); //TODO: 为什么搜索时使用0作为参数？
            if(listener == NULL){
                // 如果找不到对应的监听套接字，终止程序
                rte_exit(EXIT_FAILUER, "tcp stream seach failed\n");
            }

            // 对监听套接字的互斥锁进行加锁，以确保线程安全
            pthreadmutex_lock(&listener->mutex);
            // 触发条件变量，通知等待的线程
            pthread_cond_signal(&listener->cond);
            // 解锁互斥锁
            pthreadmutex_unlock(&listener->mutex);
        }
    }
    return 0;
}


/**
 * 处理TCP连接建立阶段的函数
 * 该函数根据接收到的TCP报文头信息，处理TCP连接的各种状态转换和数据接收
 * 
 * @param stream 指向TCP连接流的结构体指针，用于跟踪TCP连接的状态和数据
 * @param tcphdr 指向接收到的TCP报文头的指针，用于获取TCP报文的控制信息
 * @param tcplen 接收到的TCP报文的长度，用于计算数据载荷长度和校验报文完整性
 * 
 * @return 返回0表示处理成功，非0表示处理失败
 */
static int ng_tcp_handle_established(struct ng_tcp_stream * stream, struct rte_tcp_hdr * tcphdr, int tcplen){
    // 检查TCP报文中是否包含SYN标志位，用于处理连接初始化
    if(tcphdr->tcp_flags & RTE_TCP_SYN_FLAG){
        //TODO: 处理SYN标志位的逻辑，如初始化连接状态等
    }
    // 检查TCP报文中是否包含PSH标志位，用于处理数据推送
    if(tcphdr->tcp_flags & RTE_TCP_PSH_FLAG){
        // 将接收到的数据包加入到接收缓冲区队列
        ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);

        // 计算TCP头部长度，单位为32位字，用于确定数据载荷长度
        uint8_t hdrlen = tcphdr->data_off >> 4;
        // 计算数据载荷长度
        int payloadlen = tcplen - hdrlen * 4;

        // 更新接收序列号和发送序列号
        stream->rcv_nxt = stream->rcv_nxt + payloadlen;
        stream->snd_nxt = ntohl(tcphdr->recv_ack);

        // 发送确认包以确认接收数据和更新序列号
        ng_tcp_send_ackpkt(stream, tcphdr);
    }
    // 检查TCP报文中是否包含ACK标志位，用于处理确认响应
    if(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG){
        //TODO: 处理ACK标志位的逻辑，如更新序列号等
    }
    // 检查TCP报文中是否包含FIN标志位，用于处理连接终止
    if(tcphdr->tcp_flags & RTE_TCP_FIN_FLAG){
        // 更新连接状态为CLOSE_WAIT，表示接收到对方的连接终止请求
        stream->status = NG_TCP_STATUS_CLOSE_WAIT;

        // 将接收到的FIN报文加入到接收缓冲区队列
        ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);

        // 更新接收序列号和发送序列号，以确认接收到的FIN报文
        stream->rcv_nxt = stream->rcv_nxt + 1;
        stream->snd_nxt = ntohl(tcphdr->recv_ack);

        // 发送确认包以确认接收到的FIN报文
        ng_tcp_send_ackpkt(stream, tcphdr);
    }
    // 返回0表示处理成功
    return 0;
}


static int ng_tcp_handle_close_wait(struct ng_tcp_stream* stream, struct rte_tcp_hdr* tcphdr){
    if(tcphdr->tcp_flags & RTE_TCP_FIN_FLAG){
        if(stream->status == NG_TCP_STATUS_LAST_ACK){
            stream->status = NG_TCP_STATUS_CLOSED;

            printf("ng_tcp_handle_close_wait: stream closed");
            struct ng_tcp_table * table = tcpInstance();
            LL_REMOVE(stream, table->tcp_set);

            rte_ring_free(stream->sndbuf);
            rte_ring_free(stream->rcvbuf);
            rte_free(stream);
        }
    }
    return 0;
}

static int ng_tcp_handle_last_ack(struct ng_tcp_stream* stream, struct rte_tcp_hdr* tcphdr){
    if(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG){
        if(stream->status == NG_TCP_STATUS_LAST_ACK){

        }
    }
    return 0;
}


static int ng_tcp_process(struct rte_mbuf* tcpmbuf){
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr * tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);

    uint16_t tcpcksum = tcphdr->cksum;
    tcphdr->cksum = 0;
    uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);  //获取tcp/udp包头校验和，返回16位的校验和

    if(cksum != tcpcksum){
        printf("cksum: %x, tcp chsum: %x\n", cksum, tcpcksum);
        rte_pktmbuf_free(tcpmbuf);
        return -1;
    }

    struct ng_tcp_stream * stream = ng_tcp_stream_seach(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
    if(stream == NULL){
        rte_pktmbuf_free(tcpmbuf);
        return -1;
    }
    switch(stream->status){
        case NG_TCP_STATUS_CLOSED : //client
            break;

	    case NG_TCP_STATUS_LISTEN:  //server
            ng_tcp_handle_listen(stream, tcphdr, iphdr );
            break;

	    case NG_TCP_STATUS_SYN_RCVD:    //server
            ng_tcp_handle_syn_rcvd(stream, tcphdr);
            break;

	    case NG_TCP_STATUS_SYN_SENT:    //client
            break;

	    case NG_TCP_STATUS_ESTABLISHED: //server& client
            int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
            ng_tcp_handle_established(stream, tcphdr, tcplen);
            break;

	    case NG_TCP_STATUS_FIN_WAIT_1:  //client:close
            break;
	    case NG_TCP_STATUS_FIN_WAIT_2:  //client:close
            break;
	    case NG_TCP_STATUS_CLOSING: //client:close
            break;
	    case NG_TCP_STATUS_TIME_WAIT:   //client:close
            break;

	    case NG_TCP_STATUS_CLOSE_WAIT:  //server:close
            ng_tcp_handle_close_wait(stream, tcphdr);
            break;
	    case NG_TCP_STATUS_LAST_ACK:    //server:close
            ng_tcp_handle_last_ack(stream , tcphdr);
            break;
    }
    rte_pktmbuf_free(tcpmbuf);
    return 0;


}

/**
 * 处理UDP数据包
 * 
 * 该函数负责处理接收到的UDP数据包，包括获取主机信息、分配内存、填充数据包信息，
 * 以及将数据包信息发送到相应的接收缓冲区
 * 
 * @param udpmbuf 指向UDP数据包的结构体指针
 * @return 返回-1表示出错，0表示成功处理
 */
static int udp_process(struct rte_mbuf *udpmbuf) {
    // 获取IPv4头信息
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    // 获取UDP头信息
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);

    // 根据目的IP和端口获取主机信息
    struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
    if(host == NULL){
        // 如果未找到主机信息，释放数据包并返回错误
        ret_pktmbuf_free(udpmbuf);
        return -1;  
    }

    // 分配内存用于存储卸载信息
    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if(ol == NULL){
        // 如果内存分配失败，释放数据包并返回错误
        ret_pktmbuf_free(udpmbuf);
        return -1;
    }

    // 填充卸载信息
    ol->dip = iphdr->dst_addr;
    ol->sip = iphdr->src_addr;
    ol->sport = udphdr->src_port;
    ol->dport = udphdr->dst_port;
    ol->proto = IPPROTO_UDP;
    ol->length = ntohs(udphdr->dgram_len);

    // 分配内存用于存储数据负载
    ol->data = rte_malloc("unsigned_char*", ol->length - sizeof(struct rte_udp_hdr), 0);
    if(lo->data == NULL){
        // 如果内存分配失败，释放数据包和之前分配的内存，并返回错误
        ret_pktmbuf_free(udpmbuf);
        rte_free(ol);
        return -1;
    }

    // 复制数据负载到分配的内存中
    rte_memcpy(ol->data, (unsigned char * )(udphdr+1), ol->length - sizeof(struct rte_udp_hdr));

    // 将卸载信息添加到主机的接收缓冲区
    rte_ring_mp_enqueue(host->rcvbuf, ol);

    // 加锁并通知主机有新数据到达
    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    // 释放数据包
    ret_pktmbuf_free(udpmbuf);

    return 0;
}


static struct arp_table * arp_table_instance(void){
    if(arptab == NULL){
        arptab = rte_malloc("arp_table", sizeof(struct arp_table), 0);
        if(arptabl == NULL){
            rte_exit(EXIT_FAILURE,"rte_malloc apr_table faile\n");
        }
        memset(arptab , 0, sizeof(struct arp_table));

        if(pthread_spin_init(&arptab->spinlock, PTHREAD_PROCESS_SHARED ) != 0){ //初始化自旋锁
            rte_exit(EXIT_FAILURE,"arp_table pthread_spin_init failed");
        }
    }
    return arptab;
}

static uint8_t * ng_get_dst_macaddr(uint32_t ip){
    struct arp_entry *iter;
    struct arp_table * table = arp_table_instance();

    int count = table->count;
    for(iter = table->entries; (count-- != 0 && iter != NULL); iter = iter->next){
        if(ip == iter->ip){
            return iter->hwaddr;
        }
    }
    return NULL;
}

/**
 * 尝试在ARP表中插入一个新的ARP条目。
 * 
 * 当接收一个IP地址和一个MAC地址时，此函数会检查是否需要在ARP表中插入新的条目。
 * 如果当前没有与给定IP地址关联的MAC地址条目，则创建一个新的ARP条目并将其添加到ARP表中。
 * 
 * @param ip 一个32位的IP地址，用于标识需要添加到ARP表中的条目。
 * @param mac 一个指向MAC地址的指针，该MAC地址将与IP地址关联。
 * @return 返回一个整数值，如果插入成功则返回1，否则返回0。
 */
static int ng_arp_entry_insert(uint32_t ip, uint8_t *mac){
    // 获取ARP表的实例。
    struct arp_table * table = arp_table_instance();

    // 尝试从现有条目中获取与给定IP地址关联的硬件地址。
    uint8_t *hwaddr = ng_get_dst_macaddr(ip);
    if(hwaddr == NULL){
        // 如果没有找到关联的硬件地址，动态分配一个新的ARP条目结构。
        struct arp_entry * entry = rte_malloc("arp_table", sizeof(struct arp_table), 0);
        if(entry){
            // 初始化新分配的ARP条目结构。
            memset(entry, 0 , sizeof(struct arp_entry));

            // 将给定的IP地址和MAC地址关联到新的ARP条目中。
            entry->ip = ip;
            rte_memcpy(entry->mac, mac, RTE_ETHER_ADDR_LEN);
            entry->type = 0;

            // 在多线程环境下保护ARP表的操作，避免数据竞争。
            pthread_spin_lock(&table->spinlock);

            // 此处缺少释放锁的调用，可能会导致死锁。
        }

        // 插入成功，返回1。
        return 1;
    }
    // 如果已经存在关联的硬件地址，返回0，表示不需要插入新的条目。
    return 0;
}

static struct rte_mbuf * ng_send_arp(struct rte_mempool * mbuf_pool, uint16_t opcode, uint8_t * dst_mac, uint32_t sip, uint32_t dip){
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf){
        rte_exit(EXIT_FAILURE, "Failed to allocate mbuf\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);
    return mbuf;

}


static int ng_encode_udp_apppkt(uint8_t *msg , uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, unsigned char * data, uint16_t total_len){

    struct rte_ether_hdr * eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr * ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(stotal_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = htonl(sip);
    ip->dst_addr = htonl(dip);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    udp->src_port = htons(sport);
    udp->dst_port = htons(dport);
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t *)(udp + 1), data, udplen);
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
    return 0;
}


/**
 * 创建并初始化一个UDP数据包
 *
 * @param mbuf_pool 内存池句柄，用于分配mbuf
 * @param sip 源IP地址
 * @param dip 目的IP地址
 * @param sport 源端口号
 * @param dport 目的端口号
 * @param srcmac 源MAC地址
 * @param dstmac 目的MAC地址
 * @param data 数据载荷
 * @param length 数据载荷长度
 *
 * @return 返回分配好的mbuf结构体指针，若失败则返回NULL
 *
 * 此函数负责创建一个UDP数据包，它首先计算出总长度（载荷长度加固定头部长度），
 * 然后从指定的内存池中分配一个mbuf结构体。如果分配失败，函数会调用rte_exit退出程序。
 * 成功分配mbuf后，会设置其数据长度和包长度为总长度，并通过rte_pktmbuf_mtod函数将mbuf转换为uint8_t*类型，
 * 以便使用ng_encode_udp_apppkt函数进行UDP数据包的编码。最后返回mbuf指针。
 */
static struct rte_mbuf *ng_udp_pkt(struct rte_mempool * mbuf_pool, uint32_t sip, uint32_t dip, uint16_t sport , uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, uint8_t *data, uint16_t length){
    // 计算数据包总长度，包括数据载荷和固定头部
    const unsigned total_len = length + 42;
    // 从内存池分配一个mbuf结构体
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    // 如果mbuf分配失败，退出程序
    if (mbuf == NULL) {
        rte_exit(EXIT_FAILURE, "Failed to allocate mbuf\n");
    }
    // 设置mbuf的包长度和数据长度为总长度
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    // 将mbuf转换为uint8_t*类型，以便进行数据包的编码
    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t *);

    // 编码UDP数据包
    ng_encode_udp_apppkt(pktdata, sip, dip, sport , dport , srcmac, dstmac, data, total_len);
    // 返回分配好的mbuf指针
    return mbuf;
}


static int udp_out(struct rte_mempool * mbuf_pool){
    
    for(struct localhost * host = lhost; host != NULL; host = host->next){
        struct offload *ol;
        int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
        if(nb_snd < 0) continue;

        uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
        if(dstmac == NULL) {
            struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_APP_OP_REQUEST, gDefaultArpMac, ol->sip, ol->dip);

            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
            rte_ring_mp_enqueue(host->sndbuf, ol);
        } else {
            struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport, host->localmac, dstmac, oldata, ol->length);

            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);
        }

    }

    return 0;

}

static int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	// encode 
	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	// 1 ethhdr
	struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
	rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
	rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
	eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
	

	// 2 iphdr 
	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
	ip->version_ihl = 0x45;
	ip->type_of_service = 0;
	ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
	ip->packet_id = 0;
	ip->fragment_offset = 0;
	ip->time_to_live = 64; // ttl = 64
	ip->next_proto_id = IPPROTO_TCP;
	ip->src_addr = sip;
	ip->dst_addr = dip;
	
	ip->hdr_checksum = 0;
	ip->hdr_checksum = rte_ipv4_cksum(ip);

	// 3 tcphdr 

	struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
	tcp->src_port = fragment->sport;
	tcp->dst_port = fragment->dport;
	tcp->sent_seq = htonl(fragment->seqnum);
	tcp->recv_ack = htonl(fragment->acknum);

	tcp->data_off = fragment->hdrlen_off;
	tcp->rx_win = fragment->windows;
	tcp->tcp_urp = fragment->tcp_urp;
	tcp->tcp_flags = fragment->tcp_flags;

	if (fragment->data != NULL) {
		uint8_t *payload = (uint8_t*)(tcp+1) + fragment->optlen * sizeof(uint32_t);
		rte_memcpy(payload, fragment->data, fragment->length);
	}

	tcp->cksum = 0;
	tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

	return 0;
}

static struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
	uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment) {

	// mempool --> mbuf

	const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) +
							sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr) + 
							fragment->optlen * sizeof(uint32_t);

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "ng_tcp_pkt rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);

	return mbuf;

}

static int ng_tcp_out(struct rte_mempool *mbuf_pool) {

	struct ng_tcp_table *table = tcpInstance();
	
	struct ng_tcp_stream *stream;
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {

		if (stream->sndbuf == NULL) continue; // listener

		struct ng_tcp_fragment *fragment = NULL;		
		int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, (void**)&fragment);
		if (nb_snd < 0) continue;

		uint8_t *dstmac = ng_get_dst_macaddr(stream->sip); // 
		if (dstmac == NULL) {

			//printf("ng_send_arp\n");
			struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, 
				stream->dip, stream->sip);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);

			rte_ring_mp_enqueue(stream->sndbuf, fragment);

		} else {

			struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool, stream->dip, stream->sip, stream->localmac, dstmac, fragment);

			struct inout_ring *ring = ringInstance();
			rte_ring_mp_enqueue_burst(ring->out, (void **)&tcpbuf, 1, NULL);

			if (fragment->data != NULL)
				rte_free(fragment->data);
			
			rte_free(fragment);
		}

	}

	return 0;
}


/**
 * @brief 数据包处理函数
 *
 * 该函数从环形缓冲区中批量取出数据包，并根据数据包类型进行相应的处理。
 * 首先，从输入环形缓冲区中批量取出数据包。然后，对于每个取出的数据包，
 * 检查其以太网类型，如果为IPv4，则进一步检查其IP协议类型，并根据IP协议
 * 类型调用相应的处理函数。如果数据包不是IPv4类型的，或者不是由DPDK处理的，
 * 则将其发送到内核网络接口。此外，该函数还会轮询KNI请求队列，处理UDP和TCP
 * 的输出数据包。
 *
 * @param arg 传递给函数的参数，这里是内存池的指针，用于分配和回收数据包缓冲区。
 * @return 返回0表示成功。
 */
static int pkt_process(void *arg){
    // 从参数中获取mbuf内存池指针
    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    // 获取环形缓冲区实例
    struct inout_ring *ring = ringInstance();

    // 缓冲区，用于存储从环形缓冲区中取出的数据包
    struct rte_mbuf *mbufs[BURST_SIZE];
    while(1){
        // 从输入环形缓冲区中批量取出数据包
        unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void **)mbufs, BURST_SIZE, NULL);

        // 遍历取出的数据包
        unsigned i = 0;
        for(i = 0; i< num_recvd; i++){
            // 获取数据包的以太网头
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);
            // 检查以太网类型是否为IPv4
            if(eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
                // 获取数据包的IPv4头
                struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(mbufs[i], 
                                                                    struct rte_ipv4_hdr *, 
                                                                    sizeof(struct rte_ether_hdr));
                //插入一个ARP条目
                ng_arp_entry_insert(ip_hdr->src_addr, ehdr->s_addr.addr_bytes);

                // 根据IP协议类型调用相应的处理函数
                if(ip_hdr->next_proto_id == IPPROTO_UDP){
                    udp_process(mbufs[i]);
                } else if(ip_hdr->next_proto_id == IPPROTO_TCP){
                    ng_tcp_process(mbufs[i]);
                } else { 
                    // 对于其他协议类型的数据包，发送到内核网络接口
                    // TODO: 需要验证这里是否应该是mbufs[i]
                    rte_kni_tx_burst(global_kni, mbufs, num_recvd);
                }
            } else{
                // 对于非IPv4类型的数据包，发送到内核网络接口
                rte_kni_tx_burst(global_kni, mbufs, num_recvd);
            }
        }
        // 轮询KNI请求队列，处理KNI请求
        rte_kni_handle_request(global_kni);

        // 处理UDP和TCP的输出数据包
        udp_out(mbuf_pool);
        ng_tcp_out(mbuf_pool);
    }

    return 0;
}




/*
 *  初始化环形缓冲区
 *  如果已经初始化就返回已经创建好的环形缓冲区
*/
static struct inout_ring * ringInstance(void){
    if(rInst == NULL){
        rInst = rte_malloc("in/out_ring", sizeof(struct inout_ring));
        memset(rInst, 0 ,sizeof(struct inout_ring));
    }
    return rInst;
}

/*
检查网口是否可用，通过updown网口的方式
*/
static int nf_config_network_if(uint16_t port_id, uint8_t if_up){
    if(!rte_eth_dev_is_valid_port(port_id)){
        return -EINVAL;
    }
    int ret = 0;
    if(if_up){
        rte_eth_dev_stop(port_id);
        ret = rte_eth_dev_start(port_id);
    } else {
        rte_eth_dev_stop(port_id);
    }

    if(ret < 0){
        printf("Failed to start port: %d\n", port_id);
    }
    return ret;
}



/*
初始化dpdk网口
@param mbuf_pool: mbuf内存池
*/
static void ng_init_port(struct rte_mempool *mbuf_pool  ){
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();  //获取系统支持的端口数量
    if(nb_sys_ports == 0){
        rte_exit(EXIT_FAILURE, "no support eth found");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queue = 1;
    const int num_tx_queue = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(gDpdkPortId, num_rx_queue, num_tx_queue, &port_conf);
    //设置dpdk的接收队列
    if(rte_eth_rx_queue_setup(gDpdkPortId, 0, nb_desc,     
        rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool ) < 0){
            rte_exit(EXIT_FAILURE, "could not set rx queue");
    }

    #if ENABLE_SEND
    //开启发送功能
    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.rxmode.offloads;
    if(rte_eth_tx_queue_setup(gDpdkPortId, 0, nb_desc,
        rte_eth_dev_socket_id(gDpdkPortId), &txconf) < 0){
            rte_exit(EXIT_FAILURE, "could not set tx queue");
        }

    #endif

    if(rte_eth_dev_start(gDpdkPortId) < 0){
        rte_exit(EXIT_FAILURE, "could not start port %d", gDpdkPortId);
    }

    #if ENABLE_PROMISCUOUS_MODE
    rte_eth_promiscuous_enable(gDpdkPortId);
    #endif
}


/*
初始化rte_kni 模块
通过rte_kni建立虚拟网卡和内核网络的映射，即用户态可以直接获取内核态的数据
rte_kni结构体是一个KNI接口实例，可以直接获取内核网络堆栈数据
*/
static struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool){
    struct rte_kni * kni_handler = NULL;
    struct rte_kni_conf kni_conf;
    memset(&kni_conf, 0 ,sizeof(kni_conf));

    snprintf(kni_conf.name, RTE_KNI_NAMESIZE, "vEth%u", gDpdkPortId);
    kni_conf.group_id = gDpdkPortId;
    kni_conf.mbuf_size = RTE_KNI_MEMSIZE;   //
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)conf.mac_addr);
    rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);

    /*
    struct rte_kni_ops 是一个重要的结构体，
    它定义了用户态应用程序可以通过哪些操作函数与内核态的KNI（Kernel NIC Interface）接口
    进行交互。这些操作函数允许用户态应用程序对KNI接口进行配置、管理以及数据包的发送和接收等操作。
    */
    struct rte_kni_ops ops;
    memset(&ops, 0 , sizeof(ops));

    ops.port_id = gDpdkPortId;
    ops.config_network_if = nf_config_network_if;

    /*
    分配和初始化一个KNI（Kernel NIC Interface）接口的函数。
    这个函数在用户态被调用，用于创建一个新的KNI接口实例，
    并将其注册到内核态，以便用户态应用程序可以通过这个接口与内核网络堆栈进行数据交换。
    */
    kni_handler = rte_kni_alloc(mbuf_pool, &kni_conf, &ops);
    if(kni_handler == NULL){
        rte_exit(EXIT_FAILURE, "Fail to init kni\n");
    }
    return kni_handler;
}


static void* get_hostinfo_fromfd(int sockfd) {
	struct localhost *host;

	for (host = lhost; host != NULL;host = host->next) {

		if (sockfd == host->fd) {
			return host;
		}

	}

	struct ng_tcp_stream *stream = NULL;
	struct ng_tcp_table *table = tcpInstance();
	for (stream = table->tcb_set;stream != NULL;stream = stream->next) {
		if (sockfd == stream->fd) {
			return stream;
		}
	}


	return NULL;
	
}

// hook

static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused))  int protocol) {

	int fd = get_fd_frombitmap(); //

	if (type == SOCK_DGRAM) {

		struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
		if (host == NULL) {
			return -1;
		}
		memset(host, 0, sizeof(struct localhost));

		host->fd = fd;
		
		host->protocol = IPPROTO_UDP;

		host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->rcvbuf == NULL) {

			rte_free(host);
			return -1;
		}

	
		host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (host->sndbuf == NULL) {

			rte_ring_free(host->rcvbuf);

			rte_free(host);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

		LL_ADD(host, lhost);
		
	} else if (type == SOCK_STREAM) {


		struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
		if (stream == NULL) {
			return -1;
		}
		memset(stream, 0, sizeof(struct ng_tcp_stream));

		stream->fd = fd;
		stream->protocol = IPPROTO_TCP;
		stream->next = stream->prev = NULL;

		stream->rcvbuf = rte_ring_create("tcp recv buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->rcvbuf == NULL) {

			rte_free(stream);
			return -1;
		}

	
		stream->sndbuf = rte_ring_create("tcp send buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (stream->sndbuf == NULL) {

			rte_ring_free(stream->rcvbuf);

			rte_free(stream);
			return -1;
		}

		pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
		rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

		pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
		rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

		struct ng_tcp_table *table = tcpInstance();
		LL_ADD(stream, table->tcb_set); //hash
		// get_stream_from_fd();
	}

	return fd;
}

static int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused))  socklen_t addrlen) {

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct localhost *host = (struct localhost *)hostinfo;
	if (host->protocol == IPPROTO_UDP) {
		
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		host->localport = laddr->sin_port;
		rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

	} else if (host->protocol == IPPROTO_TCP) {

		struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
		
		const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
		stream->dport = laddr->sin_port;
		rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
		rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

		stream->status = NG_TCP_STATUS_CLOSED;
		
	}

	return 0;

}


static int nlisten(int sockfd, __attribute__((unused)) int backlog) { //

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	
	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {
		stream->status = NG_TCP_STATUS_LISTEN;
	}

	return 0;
}


static int naccept(int sockfd, struct sockaddr *addr, __attribute__((unused)) socklen_t *addrlen) {

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_stream *apt = NULL;

		pthread_mutex_lock(&stream->mutex);
		while((apt = get_accept_tcb(stream->dport)) == NULL) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		} 
		pthread_mutex_unlock(&stream->mutex);

		apt->fd = get_fd_frombitmap();

		struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
		saddr->sin_port = apt->sport;
		rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));

		return apt->fd;
	}

	return -1;
}


static ssize_t nsend(int sockfd, const void *buf, size_t len,__attribute__((unused)) int flags) {

	ssize_t length = 0;

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
		if (fragment == NULL) {
			return -2;
		}

		memset(fragment, 0, sizeof(struct ng_tcp_fragment));

		fragment->dport = stream->sport;
		fragment->sport = stream->dport;

		fragment->acknum = stream->rcv_nxt;
		fragment->seqnum = stream->snd_nxt;

		fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
		fragment->windows = TCP_INITIAL_WINDOW;
		fragment->hdrlen_off = 0x50;


		fragment->data = rte_malloc("unsigned char *", len+1, 0);
		if (fragment->data == NULL) {
			rte_free(fragment);
			return -1;
		}
		memset(fragment->data, 0, len+1);

		rte_memcpy(fragment->data, buf, len);
		fragment->length = len;
		length = fragment->length;

		// int nb_snd = 0;
		rte_ring_mp_enqueue(stream->sndbuf, fragment);

	}

	
	return length;
}

// recv 32
// recv 
static ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags) {
	
	ssize_t length = 0;

	void *hostinfo =  get_hostinfo_fromfd(sockfd);
	if (hostinfo == NULL) return -1;

	struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
	if (stream->protocol == IPPROTO_TCP) {

		struct ng_tcp_fragment *fragment = NULL;
		int nb_rcv = 0;

		printf("rte_ring_mc_dequeue before\n");
		pthread_mutex_lock(&stream->mutex);
		while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
			pthread_cond_wait(&stream->cond, &stream->mutex);
		}
		pthread_mutex_unlock(&stream->mutex);
		printf("rte_ring_mc_dequeue after\n");

		if (fragment->length > len) {

			rte_memcpy(buf, fragment->data, len);

			uint32_t i = 0;
			for(i = 0;i < fragment->length-len;i ++) {
				fragment->data[i] = fragment->data[len+i];
			}
			fragment->length = fragment->length-len;
			length = fragment->length;

			rte_ring_mp_enqueue(stream->rcvbuf, fragment);

		} else if (fragment->length == 0) {

			rte_free(fragment);
			return 0;
		
		} else {

			rte_memcpy(buf, fragment->data, fragment->length);
			length = fragment->length;

			rte_free(fragment->data);
			fragment->data = NULL;

			rte_free(fragment);
			
		}

	}

	return length;
}


static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused))  int flags,
                        struct sockaddr *src_addr, __attribute__((unused))  socklen_t *addrlen) {

	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	struct offload *ol = NULL;
	unsigned char *ptr = NULL;
	
	struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
	
	int nb = -1;
	pthread_mutex_lock(&host->mutex);
	while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
		pthread_cond_wait(&host->cond, &host->mutex);
	}
	pthread_mutex_unlock(&host->mutex);
	

	saddr->sin_port = ol->sport;
	rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

	if (len < ol->length) {

		rte_memcpy(buf, ol->data, len);

		ptr = rte_malloc("unsigned char *", ol->length-len, 0);
		rte_memcpy(ptr, ol->data+len, ol->length-len);

		ol->length -= len;
		rte_free(ol->data);
		ol->data = ptr;
		
		rte_ring_mp_enqueue(host->rcvbuf, ol);

		return len;
		
	} else {

		int length = ol->length;
		rte_memcpy(buf, ol->data, ol->length);
		
		rte_free(ol->data);
		rte_free(ol);
		
		return length;
	}

	

}

static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused))  int flags,
                      const struct sockaddr *dest_addr, __attribute__((unused))  socklen_t addrlen) {

	
	struct localhost *host =  get_hostinfo_fromfd(sockfd);
	if (host == NULL) return -1;

	const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

	struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
	if (ol == NULL) return -1;

	ol->dip = daddr->sin_addr.s_addr;
	ol->dport = daddr->sin_port;
	ol->sip = host->localip;
	ol->sport = host->localport;
	ol->length = len;

	struct in_addr addr;
	addr.s_addr = ol->dip;
	printf("nsendto ---> src: %s:%d \n", inet_ntoa(addr), ntohs(ol->dport));
	

	ol->data = rte_malloc("unsigned char *", len, 0);
	if (ol->data == NULL) {
		rte_free(ol);
		return -1;
	}

	rte_memcpy(ol->data, buf, len);

	rte_ring_mp_enqueue(host->sndbuf, ol);

	return len;
}

static int nclose(int fd) {

	
	void *hostinfo =  get_hostinfo_fromfd(fd);
	if (hostinfo == NULL) return -1;

	struct localhost *host = (struct localhost*)hostinfo;
	if (host->protocol == IPPROTO_UDP) {

		LL_REMOVE(host, lhost);

		if (host->rcvbuf) {
			rte_ring_free(host->rcvbuf);
		}
		if (host->sndbuf) {
			rte_ring_free(host->sndbuf);
		}

		rte_free(host);

		set_fd_frombitmap(fd);
		
	} else if (host->protocol == IPPROTO_TCP) { 

		struct ng_tcp_stream *stream = (struct ng_tcp_stream*)hostinfo;

		if (stream->status != NG_TCP_STATUS_LISTEN) {
			
			struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
			if (fragment == NULL) return -1;

			printf("nclose --> enter last ack\n");
			fragment->data = NULL;
			fragment->length = 0;
			fragment->sport = stream->dport;
			fragment->dport = stream->sport;

			fragment->seqnum = stream->snd_nxt;
			fragment->acknum = stream->rcv_nxt;

			fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
			fragment->windows = TCP_INITIAL_WINDOW;
			fragment->hdrlen_off = 0x50;

			rte_ring_mp_enqueue(stream->sndbuf, fragment);
			stream->status = NG_TCP_STATUS_LAST_ACK;

			
			set_fd_frombitmap(fd);

		} else { // nsocket

			struct ng_tcp_table *table = tcpInstance();
			LL_REMOVE(stream, table->tcb_set);	

			rte_free(stream);

		}
	}

	return 0;
}


//__attribute__((unused))这个属性被用于指示编译器，arg这个参数在函数体内没有被使用，但这是一个合法的、故意为之的情况。
/*

    回调函数：当定义一个回调函数时，有时候函数的签名（包括参数列表）是由外部库或API定义的，而你的回调实现中可能并不需要所有提供的参数。使用__attribute__((unused))可以避免编译器因未使用参数而发出的警告。

    兼容性：在维护旧代码或需要保持与特定API兼容时，即使某些参数在当前实现中未使用，也需保留这些参数。此时，__attribute__((unused))可以清除编译器的警告。

    代码清晰性：通过明确标记未使用的参数，可以使得代码更容易被其他开发者理解，知道这些参数是故意未使用的，而不是遗漏了对其的处理。
*/
/**
 * UDP服务器端口函数
 * 创建UDP套接字，绑定到指定端口，并循环接收客户端发送的数据
 * 当接收到数据时，打印数据内容并原样发送回客户端
 * 
 * @param arg 传递给函数的参数，本函数中未使用
 * @return 返回-1表示socket创建失败，否则永不返回
 */
struct int udp_server_entry(__attribute__ (unused) void * arg){
    // 创建UDP套接字
    int connfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (connfd == -1) {
        printf("sockfd failed\n");
        return -1;
    }

    // 初始化服务器地址结构
    struct sockaddr_in localaddr, clientaddr; // struct sockaddr 
    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    // 设置本地地址和端口
    localaddr.sin_port = htons(8889);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = inet_addr(LOCALADDR); // 0.0.0.0

    // 绑定套接字到本地地址
    nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

    // 定义接收缓冲区
    char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
    socklen_t addrlen = sizeof(clientaddr);

    // 循环接收和发送数据
    while (1) {

        // 尝试接收数据
        if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0, 
            (struct sockaddr*)&clientaddr, &addrlen) < 0) {

            // 接收失败，继续循环
            continue;

        } else {

            // 打印接收到的数据信息，并发送回客户端
            printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr), 
                ntohs(clientaddr.sin_port), buffer);
            nsendto(connfd, buffer, strlen(buffer), 0, 
                (struct sockaddr*)&clientaddr, sizeof(clientaddr));
        }
    }

    // 关闭套接字
    nclose(connfd);
}


static int tcp_server_entry(__attribute__((unused))  void *arg)  {

	int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1) {
		return -1;
	}

	struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(struct sockaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(9999);
	nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

	nlisten(listenfd, 10);


	int epfd = epoll_create(1);	

	struct epoll_event ev;	
	ev.events = EPOLLIN;	
	ev.data.fd = listenfd;	
	epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);

	struct sockaddr_in  clientaddr;	
	socklen_t len = sizeof(clientaddr);

	while (1) {		
		struct epoll_event events[1024] = {0};		
		int nready = epoll_wait(epfd, events, 1024, -1);

		int i = 0;		
		for (i = 0;i < nready;i ++) {
			int connfd = events[i].data.fd;			//这里返回的是实际的fd，是真的epoll获取到的套接字
			if (connfd == listenfd) {								
				int clientfd = naccept(listenfd, (struct sockaddr*)&clientaddr, &len);	
				printf("accept finshed: %d\n", clientfd);				
				ev.events = EPOLLIN;				
				ev.data.fd = clientfd;				
				epoll_ctl(epfd, EPOLL_CTL_ADD, clientfd, &ev);	
				
			} else if (events[i].events & EPOLLIN) {				
				char buffer[1024] = {0};								
				int count = nrecv(connfd, buffer, 1024, 0);
				
				if (count == 0) { // disconnect					
					printf("client disconnect: %d\n", connfd);					
					nclose(connfd);					
					epoll_ctl(epfd, EPOLL_CTL_DEL, connfd, NULL);	
					continue;				
				}				
				printf("RECV: %s\n", buffer);				
				count = nsend(connfd, buffer, count, 0);				
				printf("SEND: %d\n", count);			
			}
		}
	}
	nclose(listenfd);
	

}

int main(int argc, char **argv[]){
    //dpdk环境初始化
    if(rte_eal_init(argc, argv)){
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
    }
    //创建dpdk的buf池
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",NUM_MBUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(mbuf_pool == NULL){
        rte_exit(EXIT_FAILURE, "create mbuf pool failed");
    }

    ng_init_port(mbuf_pool);
    global_kni = ng_alloc_kni(mbuf_pool);
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

#if ENABLE_RINGBUFFER
    struct inout_ring *ring = ringInstance();
    if(ring == NULL){
        rte_exit(EXIT_FAILURE, "create ring failed");
    }
    if(ring->in == NULL){
        ring->in = rte_ring_create("in_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
    if(ring->out == NULL){
        ring->out = rte_ring_create("out_ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
#endif

    //将线程函数注册到对应的逻辑核心上，
    if(rte_eal_remote_launch(pkt_process, mbuf_pool, rte_get_next_lcore()) < 0){
        rte_exit(EXIT_FAILURE, "rte_eal_remote_launch pkt_process failed");
    }

    if(rte_eal_remote_launch(udp_server_entry, mbuf_pool, rte_get_next_lcore()) < 0){
        rte_exit(EXIT_FAILURE, "rte_eal_remote_launch udp_server_entry failed");
    }

    if(rte_eal_remote_launch(tcp_server_entry, mbuf_pool, rte_get_next_lcore()) < 0){
        rte_exit(EXIT_FAILURE, "rte_eal_remote_launch udp_server_entry failed");
    }


	while (1) {
		// rx
		struct rte_mbuf *rx[BURST_SIZE];
		unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
		if (num_recvd > BURST_SIZE) {
			rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
		} else if (num_recvd > 0) {
			rte_ring_sp_enqueue_burst(ring->in, (void**)rx, num_recvd, NULL);
		}

		
		// tx
		struct rte_mbuf *tx[BURST_SIZE];
		unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx, BURST_SIZE, NULL);
		if (nb_tx > 0) {

			rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

			unsigned i = 0;
			for (i = 0;i < nb_tx;i ++) {
				rte_pktmbuf_free(tx[i]);
			}
			
		}
		

	}



    return 0;
}