
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

#define FILE_PATH "./hook.txt"
#define PORT 2000

ucontext_t ctx[3] ,main_ctx;
int count = 0;
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

void func1(void){
    while(count < 6){
        count++;
        printf("fun1 start %d\n", count);
        swapcontext(&ctx[0], &main_ctx);
        printf("fun1 end %d\n", count);
    }
}


void func2(void){
    while(count < 6){
        count++;
        printf("fun2 start %d\n", count);
        swapcontext(&ctx[1], &main_ctx);
        printf("fun2 end %d\n",count );
    }
}

void func3(void){
    while(count < 6){
        count++;
        printf("fun3 start %d\n", count);
        swapcontext(&ctx[2], &main_ctx);
        printf("fun3 end %d\n", count);
    }
}

int main(int argc, char** argv){
    //hook_init();
    //printf("after hook\n");
    #if 0
    #if 1
    int file_fd = open(FILE_PATH, O_CREAT | O_RDWR);
    if(file_fd < 0){
        perror("open");
        return -1;
    }
    #else
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
    #endif
    #endif
    
    char stack1[2048] = {0};
    char stack2[2048] = {0};
    char stack3[2048] = {0};
    //getcontext(&main_ctx);
    getcontext(&ctx[0]);
    ctx[0].uc_stack.ss_sp = stack1;
    ctx[0].uc_stack.ss_size = sizeof(stack1);
    ctx[0].uc_link = &main_ctx;
    makecontext(&ctx[0], func1, 0);
    
    getcontext(&ctx[1]);
    ctx[1].uc_stack.ss_sp = stack2;
    ctx[1].uc_stack.ss_size = sizeof(stack2);
    ctx[1].uc_link = &main_ctx;
    makecontext(&ctx[1], func2, 0);

    getcontext(&ctx[2]);
    ctx[2].uc_stack.ss_sp = stack3;
    ctx[2].uc_stack.ss_size = sizeof(stack3);
    ctx[2].uc_link = &main_ctx;
    makecontext(&ctx[2], func3, 0);
    
    printf("swapcontext\n");
    getcontext(&main_ctx);
    while(count < 6){
        swapcontext(&main_ctx, &ctx[count % 3]);        
    }

    printf("&&&&&&&&&&&&&\n");
    
    
    return 0;
}