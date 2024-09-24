#include "server.h"

int recv_cb(int fd);
int send_cb(int fd);
int accept_cb(int fd);
int set_event(int fd, int events, int flag);




struct conn *conn_fd = NULL; 
static int epfd = 0;
static int conn_num = 0;


int recv_cb(int fd){
    if (fd < 0) return -1;
    memset(conn_fd[fd].rbuffer, 0, BUFFER_LENGTH );
    int count = recv(fd, conn_fd[fd].rbuffer, BUFFER_LENGTH, 0);
    if (count == 0) { // 
        printf("client disconnect: %d\n", fd);
        close(fd);
        conn_num--;
        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL); // unfinished
        return 0;
    } else if (count < 0) { // 

        printf("count: %d, errno: %d, %s\n", count, errno, strerror(errno));
        close(fd);
        conn_num--;
        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
        return 0;
    }
    //printf("fd[%d] recv:%s\n",fd, conn_fd[fd].rbuffer);
    conn_fd[fd].rlength = count;
    #if HTTP_ENABLE
        http_request(&conn_fd[fd]);
    #elif WS_ENABLE
        ws_request(&conn_fd[fd]);
    #elif KVS_ENABLE
        kvs_request(&conn_fd[fd]);
    #endif
    set_event(fd, EPOLLOUT, 0);

    return count;
}

int send_cb(int fd){
    if (fd < 0) return -1;
    #if HTTP_ENABLE
        http_response(&conn_fd[fd]);
    #elif WS_ENABLE
        ws_response(&conn_fd[fd]);
    #elif KVS_ENABLE
        kvs_response(&conn_fd[fd]);
    #endif
    int count = 0;
    if (conn_fd[fd].wlength != 0) {
         count = send(fd, conn_fd[fd].wbuffer, conn_fd[fd].wlength, 0);
    }

    set_event(fd, EPOLLIN , 0);
    return count;
}
//fd事件注册，顺便设置事件
int event_register(int fd, int event ){
    if (fd < 0) return -1;
    conn_fd[fd].fd = fd;
    conn_fd[fd].r_action.accept_callback = recv_cb;
    conn_fd[fd].send_callback = send_cb;
    memset(conn_fd[fd].wbuffer, 0, BUFFER_LENGTH);
    memset(conn_fd[fd].rbuffer, 0, BUFFER_LENGTH);
    conn_fd[fd].rlength = 0;
    conn_fd[fd].wlength = 0;
    //printf("event_register connfd[%d] is %d\n", fd, conn_fd[fd].fd);
    set_event(fd, event , 0);
}

int accept_cb(int fd){
    if (fd < 0) return -1;
    struct sockaddr_in clientaddr;
    socklen_t len = sizeof(clientaddr);
    int connfd = accept(fd, (struct sockaddr *)&clientaddr, &len);
    if(connfd == -1){
        perror("accept");
        return -1;
    }
    conn_num++;
    
    event_register(connfd,EPOLLIN);
    //时间
    //printf("accept finshed : %d\n", connfd);
    if ((conn_num % 1000) == 0) {
        printf("accept finshed: %d\n", conn_num);
    }
    return 0;
}


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

int set_event(int fd, int events, int flag)
{
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = events;
    if(flag){
        return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    }
    else {
        return epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev);
    }
}

int main(int argc, char *argv[])
{
    int port = 2000;
    conn_fd = (struct conn *)malloc(sizeof(struct conn) * CONNECTION_SIZE);
    if (conn_fd == NULL) {
        // 处理内存分配失败的情况，例如打印错误信息或者退出程序
        printf("Failed to allocate memory for conn_fd.\n");
        exit(EXIT_FAILURE);
    }
    memset(conn_fd, 0, sizeof(struct conn) * CONNECTION_SIZE);
    
    epfd = epoll_create(1); 
    if(epfd == -1){
        perror("epoll_create");
        return -1;
    }

    for (int i = 0; i < MAX_PORTS; i++)
    {
        int sockfd = init_server(port + i);
        if(sockfd == -1){
            perror("init_server");
            return -1;
        }

        conn_fd[sockfd].fd = sockfd;
        conn_fd[sockfd].r_action.recv_callback = accept_cb;
        //printf("initserver conn_fd[%d].fd = %d\n", i, conn_fd[i].fd);

        set_event(conn_fd[sockfd].fd, EPOLLIN, 1);
        //printf("server start on port %d\n", PORT + i);
    }

    //这里为什么设置的是1024呢？
    //这里是否应该放在while之外：放在while之外会有很多好处，避免了资源在栈区的频繁创建和释放
    //这里需要设置一个动态的数组调整，通过nfds和事件的多少来判断是否需要动态调整
    struct epoll_event events[1024] = {0};
    int connfd = 0;

    while(1){
        memset(events, 0, sizeof(events));  
        int nready = epoll_wait(epfd, events, 1024, -1);
        //二是将监听fd也写到回调中
        for(int i = 0; i < nready; i++){
            connfd = events[i].data.fd;
            if(events[i].events & EPOLLIN){
                //printf("epollin connfd[%d].fd = %d\n", connfd,conn_fd[connfd].fd);
                conn_fd[connfd].r_action.recv_callback(connfd);
            }
            if(events[i].events & EPOLLOUT){
                conn_fd[connfd].send_callback(connfd);
            }
        }

    }
    free(conn_fd);
    conn_fd = NULL;
    return 0;
}
