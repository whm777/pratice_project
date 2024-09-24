#ifndef SERVER_H
#define SERVER_H



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/epoll.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>



#define BUFFER_LENGTH 1024
#define MAX_PORTS 20
#define EPOLL_TEST
#define CONNECTION_SIZE 1048576

typedef int (*RCALLBACK)(int fd);

struct conn {
    int fd;

    char rbuffer[BUFFER_LENGTH];
    int rlength;
    char wbuffer[BUFFER_LENGTH];
    int wlength;

    RCALLBACK send_callback;

    //recv和accept的回调函数，他俩都是属于epollin事件的回调
    union{
        RCALLBACK recv_callback;
        RCALLBACK accept_callback;
    }r_action;

    int status;
    char *payload;
    char mask[4];//?
};

int http_request(struct conn* c);
int http_response(struct conn* c);

int ws_request(struct conn* c); //?
int ws_response(struct conn* c);

#endif