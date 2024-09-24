#include "server.h"


/*
@args:
rmsg:request message
length: request message length
response:need to send to client
@return: length of response
*/
int kvs_protocol(char *rmsg, int length, char * response){
    printf("read from server: %d, %s\n", length, rmsg);
    return 0;
}


int kvs_request(struct conn *c){
    printf("recv %d: %s\n", c->rlength, c->rbuffer);
    c->wlength = kvs_protocol(c->rbuffer, c->rlength, c->wbuffer);
    return 0;
}


int kvs_response(struct conn *c ){
    
    return 0;
}