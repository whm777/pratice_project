
#define _GNU_SOURCE

#include <dlfcn.h>  
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <poll.h>
#include <ucontext.h>

#include <unistd.h> 

//#define FILE_PATH "./hook.txt"
#define PORT 2000
/*自建一个hook，自定义读写文件的read和write*/

typedef ssize_t (*read_hook)(int fd, void *buf, size_t count);
typedef ssize_t (*write_hook)(int fd,const void *buf, size_t count);

read_hook old_read = NULL;
write_hook old_write = NULL;

int hook_init(){
    // printf("in hook\n");
    if(!old_read){
        old_read = (read_hook)dlsym(RTLD_NEXT, "read");
    }
    if(!old_write){
        old_write = (write_hook)dlsym(RTLD_NEXT, "write");
    }
    //printf("out hook\n");
}

ssize_t read(int fd, void *buf, size_t count){
    struct pollfd fds[1] = {0};
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    
    int ret = poll(fds, 1 , 0);
    if(ret <= 0 ){
        //没有事件发生，协程切换。
        swapcontext(0,0);
    }
    ssize_t res = old_read(fd, buf, count);
    printf("read:%s\n", (char *)buf);
    return res;
}

ssize_t write(int fd, const void *buf, size_t count){
    //printf("hook write\n");
    return old_write(fd, buf, count);
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



int main(int argc, char** argv){
    hook_init();
    //printf("after hook\n");
    #if 0
    int file_fd = open(FILE_PATH, OW_RDONLY);
    #endif
    int sock_fd = init_server(PORT);
    char* buf = (char*)malloc(128);
    while(1){
        int ret = read(sock_fd, buf, 128);
         if(ret == 0){
            break;
        }
        
        write(sock_fd, buf, ret);
        printf("read %d bytes from %d\n", ret,sock_fd);
        printf("%s\n", buf);
       
    }
    
    free(buf);
    buf = NULL;
    close(sock_fd);
    return 0;
}