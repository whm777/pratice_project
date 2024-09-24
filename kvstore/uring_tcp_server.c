/**
 * 网络用iouring实现tcp服务器
 * */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>


#include "liburing.h"

#define EVENT_ACCEPT 0
#define EVENT_READ 1
#define EVENT_WRITE 2

extern int kvs_protocol(char *request, int request_length, char *response);

struct conn_info{
    int fd;
    int event;
};

#define ENTRIES_LENGTH 1024
#define BUFFER_LENGTH 1024

int init_server(unsigned int port){
    struct sockaddr_in servaddr;
    int opt = 1;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        perror("socket");
        return -1;
    }
    /*
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }*/
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
    if(bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1){
        perror("bind");
        return -1;
    }
    if (listen(sockfd, 10) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

//set_event_***这几个的代码可以重新编写一下，复用部分代码
int set_event_send(struct io_uring *ring, int sockfd, void *buf, size_t len, int flags){
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    struct conn_info accept_info = {
        .fd = sockfd,
        .event = EVENT_WRITE,
    };
    //这里会设置很重要的一个参数SQE
    io_uring_prep_send(sqe, sockfd, buf, len, flags);
    memcpy(&sqe->user_data, &accept_info, sizeof(struct conn_info));
}

int set_event_recv(struct io_uring *ring, int sockfd, void *buf, size_t len, int flags){
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    struct conn_info accept_info = {
        .fd = sockfd,
        .event = EVENT_ACCEPT,
    };
    io_uring_prep_recv(sqe, sockfd, buf, len, flags);
    memcpy(&sqe->user_data, &accept_info, sizeof(struct conn_info));
}


int set_event_accept(struct io_uring *ring, int sockfd, struct sockaddr *cliaddr, socklen_t *len, int flags){
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    struct conn_info accept_info = {
        .fd = sockfd,
        .event = EVENT_ACCEPT,
    };

    io_uring_prep_accept(sqe, sockfd, cliaddr, len, flags);
    memcpy(&sqe->user_data, &accept_info, sizeof(struct conn_info));
}


int main(int argc, char **argv)
{
    #if 0
    if (argc <= 2) {
		printf("Usage: %s ip port\n", argv[0]);
		exit(0);
	}
    #endif

    unsigned short port = 9999;
    int sockfd = init_server(port);

    //初始化io_uring结构体
    struct io_uring ring;
    memset(&ring, 0 , sizeof(ring));
    //params是ring的配置结构体，可以定义io_uring的属性和行为
    struct io_uring_params params;
    memset(&params, 0 , sizeof(params));
    io_uring_queue_init_params(ENTRIES_LENGTH, &ring, &params);
    printf("after io_uring_queue_init_params\n");

    //获取SQE，代表提交队列，SQE的不同决定了执行不同的操作，比如：文件读写，网络套接字操作.
    struct io_uring_sqe *sqe = NULL;

    struct sockaddr *cliaddr;
    socklen_t len = sizeof(cliaddr);

    set_event_accept(&ring, sockfd, cliaddr, &len, 0);
    printf("after set_event_accept\n");
    char buffer[BUFFER_LENGTH] = {0};
    while(1){
        //将ring 提交到内核
        io_uring_submit(&ring);
        //printf("after io_uring_submit\n");

        struct io_uring_cqe *cqe;
        //阻塞等待cqe
        io_uring_wait_cqe(&ring, &cqe);

        struct io_uring_cqe *cqes[128];
        int nready = io_uring_peek_batch_cqe(&ring, cqes , 128);
        for(int i = 0; i < nready; i++){
            struct io_uring_cqe * entries = cqes[i];
            struct conn_info result;
            memcpy(&result, &(entries->user_data), sizeof(struct conn_info));

            if(result.event == EVENT_ACCEPT){
                set_event_accept(&ring, result.fd, cliaddr, &len, 0);
                int connfd = entries->res;
                set_event_recv(&ring, connfd, buffer, BUFFER_LENGTH, 0);
            }
            else if (result.event == EVENT_READ){
                int ret = entries->res;
                char *recv_buffer = io_uring_cqe_get_data(entries);
                printf("read %d\n", ret);
                if(ret ==0){
                    close(result.fd);
                }
                else if (ret > 0){
                    char response[1024] = {0};
                    int res_length =  kvs_protocol(recv_buffer, ret, response);
                    set_event_send(&ring, result.fd, response, res_length, 0);
                
                    //printf("buffer size:%d ; is %s\n",ret, recv_buffer);
                }
            }else if(result.event == EVENT_WRITE){
                int ret = entries->res;
                set_event_recv(&ring, result.fd, buffer, BUFFER_LENGTH, 0);
                
            }
        }
        io_uring_cq_advance(&ring, nready);
    }
    //对uiring资源进行清理
    io_uring_queue_exit(&ring);
}
