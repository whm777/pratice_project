#include "server.h"


int http_request(struct conn* c){
    memset(c->wbuffer, 0 , BUFFER_LENGTH);
    c->wlength = 0;
    c->status = 0;
    return 0;
}

int http_response(struct conn* c){
    #if 1 
        c->wlength = sprintf(c->wbuffer, 
        "http/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Accept-Ranges:bytes\r\n"
        "Content-Length: %d\r\n"
        "Date: %s\r\n"
        "<html><head><title>%s</title></head><body>%s</body></html>\r\n\r\n", 
        strlen(c->payload), 
        time_string(), 
        "hello world", 
        "piss of shit"
        );
    #endif 
    return c->wlength;
}

