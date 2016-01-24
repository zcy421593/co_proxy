
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include "event.h"
#include "dns.h"
#include "list.h"
#include "coroutine.h"
#include <assert.h>
#include "co_base.h"

#define CACHE_HASH_BUCKET_SIZE 4096
#define HASH_BUCKET_SIZE 512
#define WORKSPACE_SIZE 512
#define NAME_SIZE      16 

struct cache_record {
    list_head list;
    char cname[256];
    char host[256];
    char ip[64];
};

struct request_record {
    char host[256];
};

struct response_record {
    int type;
    char ip[64];
    char cname[256];
    char host[256];
};

struct dns_req {
    bool is_canceled;
    list_head list;
    int task_id;
    bool is_ip;
    struct dns_real_req* real_req;
    const char* right_result;
    const char* right_cname;
    event* tmr_complete;
};

struct dns_real_req {
    list_head list;
    list_head list_reqs;
    bool pending;
    char host[256];
    int count_timeout;
    event* tmr_retry;
};

static struct co_base* s_base = NULL;
static int s_fd = 0;
static struct event* s_event = NULL;

static char s_ns_addr[255] = {};

static list_head s_hash[HASH_BUCKET_SIZE] = {};

static list_head s_cache_hash[CACHE_HASH_BUCKET_SIZE] = {};

static struct sockaddr_in s_server_addr = {};

static void dns_real_req_start(struct dns_real_req* real_req);

static void dns_recv_cb(int fd, short what, void* args);

static int dns_send_req(const char* host);

static void dns_real_req_active_and_free(struct dns_real_req* req, 
                                         struct response_record* resps,
                                         int resp_count,
                                         int ret_code);

static int dns_hash_str(const char* str) {
    uint64_t total = 0;
    while(*str) {
        total += *str;
        str++;
    }
    return total % HASH_BUCKET_SIZE;
}

static int dns_hash_cache_str(const char* str) {
    uint64_t total = 0;
    while(*str) {
        total += *str;
        str++;
    }
    return total % CACHE_HASH_BUCKET_SIZE;
}

static struct cache_record* dns_cache_find(const char* host) {
    int i = dns_hash_cache_str(host);
    struct cache_record* pos;
    list_for_each_entry(pos, &s_cache_hash[i], list) {
        if(strcmp(pos->host, host) == 0) {
            return pos;
        }
    }
    return NULL;
}

static void dns_cache_add(const char* host, const char* ip, const char* cname) {
    if(dns_cache_find(host) != NULL) {
        return;
    }
    int i = dns_hash_cache_str(host);
    struct cache_record* record = (struct cache_record*)calloc(1, sizeof(struct cache_record));
    strncpy(record->host, host, sizeof(record->host));
    strncpy(record->ip, ip, sizeof(record->ip));
    strncpy(record->cname, cname, sizeof(record->ip));
    list_add_tail(&record->list, &s_cache_hash[i]);
}

static void dns_real_req_timercb(int fd, short what, void* args) {
    struct dns_real_req* real_req = (struct dns_real_req*)args;
    real_req->count_timeout ++;
    //if(real_req->count_timeout >= 5) {
        dns_real_req_active_and_free(real_req, NULL, 0, -1);
    //} else {
    //    dns_real_req_start(real_req);
    //}
}

static struct dns_real_req* dns_real_req_find(const char* host) {
    int pos = dns_hash_str(host);
    struct dns_real_req* p = NULL;
    list_for_each_entry(p, &s_hash[pos], list) {
        if(strncmp(p->host, host, sizeof(p->host)) == 0) {
            return p;
        }
    }
    return NULL;
}

static void dns_real_req_add(struct dns_real_req* real_req) {
    int pos = dns_hash_str(real_req->host);
    list_add_tail(&real_req->list, &s_hash[pos]);
}

static void dns_real_req_start(struct dns_real_req* real_req) {
    timeval val= {5, 0};
    evtimer_add(real_req->tmr_retry, &val);
    dns_send_req(real_req->host);
}

static void dns_activecb(int fd, short what, void* args) {
    dns_req* req = (dns_req*)args;
    event_free(req->tmr_complete);
    coroutine_resume(s_base->sch, req->task_id);
}

static void dns_real_req_active_and_free(struct dns_real_req* req, 
                                         struct response_record* resps,
                                         int resp_count,
                                         int ret_code) {
    printf("dns_real_req_active_and_free\n");
    int i = 0;
    struct dns_req* pos = NULL;
    struct dns_req* n = NULL;
    const char * ip = NULL;
    int ip_count = 0;
    const char* cname = NULL;

    if(resp_count > 0) {
        for(i = 0; i < resp_count; i++) {
            if(resps[i].type == 1) {
                //fprintf(stderr, "setting ip:%s\n", resps[i].ip);
                ip = resps[i].ip;		
                break;
            } else if(resps[i].type == 5) {
		cname = resps[i].cname;
	    }
        }
    }
    
    if(!cname) {
        cname = "";
    }

    if(!ip) {
      ret_code = -1;
    }

    if(resp_count == 0 & ret_code == 0) {
        ret_code = -1;
    }

    if(req->tmr_retry) {
        evtimer_del(req->tmr_retry);
        event_free(req->tmr_retry);
        req->tmr_retry = NULL;
    }
    
    if(ret_code == 0 && ip) {
	printf("adding cache,host=%s, cname=%s, ip=%s\n", req->host, cname, ip);
        dns_cache_add(req->host, ip, cname);
    }

    list_for_each_entry_safe(pos, n, &req->list_reqs, list) {
        timeval val= {};
        printf("pos->taskid=%d\n", pos->task_id);
        pos->tmr_complete = evtimer_new(s_base->base, dns_activecb, pos);
        evtimer_add(pos->tmr_complete, &val);
        list_del(&pos->list);
    }

    // delete from hash table
    list_del(&req->list);
    free(req);
}

int dns_init(struct co_base* base, const char* ns_addr) {
    int i = 0;
    s_base = base;
    s_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    evutil_make_socket_nonblocking(s_fd);
    strncpy(s_ns_addr, ns_addr, sizeof(s_ns_addr));
    s_event = event_new(s_base->base, s_fd, EV_READ, dns_recv_cb, NULL);
    event_add(s_event, NULL);
    s_server_addr.sin_family = AF_INET;
    s_server_addr.sin_port = htons(53);
    s_server_addr.sin_addr.s_addr = inet_addr(ns_addr);

    for(i = 0; i < HASH_BUCKET_SIZE; i++) {
        INIT_LIST_HEAD(&s_hash[i]);
    }

    for(i = 0; i < CACHE_HASH_BUCKET_SIZE; i++) {
        INIT_LIST_HEAD(&s_cache_hash[i]);
    }

    return 0;
}

const char* dns_resolve(const char* host) {
    printf("resolve start\n");
    struct dns_req* req = NULL;
    struct in_addr inaddr;
    if (inet_aton(host, &inaddr)) {        
        return inet_ntoa(inaddr);
    }

    struct cache_record* record = dns_cache_find(host);

    if(record) {
        fprintf(stderr, "host %s cached\n", host);
        return record->ip;
    }

    printf("cache not found\n");
    req = (struct dns_req*)calloc(1, sizeof(struct dns_req));
    req->task_id = coroutine_running(s_base->sch);
    printf("taskid=%d\n", req->task_id);
    struct dns_real_req* real_req = dns_real_req_find(host);
    if(!real_req) {
        real_req = (struct dns_real_req*)calloc(1, sizeof(struct dns_real_req));
        real_req->tmr_retry = evtimer_new(s_base->base, dns_real_req_timercb, real_req);

        INIT_LIST_HEAD(&real_req->list_reqs);
        strncpy(real_req->host, host, sizeof(real_req->host));
        dns_real_req_add(real_req);
        dns_real_req_start(real_req);
    }

    list_add_tail(&req->list, &real_req->list_reqs);

    printf("dns req sent\n");
    coroutine_yield(s_base->sch); 
    free(req);
    record = dns_cache_find(host);
    if(record) {
        return record->ip;
    } else {
        return NULL;
    }
}

static unsigned char *install_domain_name(unsigned char *p, const char *domain_name)
{
    // .lemuria.cis.vtc.edu\0
    *p++ = '.';
    strcpy((char *)p, domain_name);
    p--;

    while (*p != '\0') {
        if (*p == '.') {
            unsigned char *end = p + 1;
            while (*end != '.' && *end != '\0') end++;
            *p = end - p - 1;
        }
        p++;
    }
    return p + 1;
}

static unsigned char* decode_enc_str(unsigned char* msg_begin, unsigned char* p, char* buf) {
    while(*p) {
        int len = *p;

        if(len == 0xc0) {
            int offset = (*p & 0x3f) * 255 + (*(p + 1));
            decode_enc_str(msg_begin, msg_begin + offset, buf);
            p += 2;
            return p;
        } else {
            p ++;
            memcpy(buf + strlen(buf), p, len);
            strcat(buf, ".");
            p += len;
        }
    }
    buf[strlen(buf) - 1] = 0;
    p ++;
    return p;
}

static unsigned char* decode_request_items(unsigned char* msg_begin, unsigned char* p, struct request_record* rec) {
    p = decode_enc_str(msg_begin, p, rec->host);
    printf("host = %s\n", rec->host);
    p += 4;
    return p;
}



static unsigned char* decode_resopnse_item(unsigned char* msg_begin, unsigned char* p, struct response_record* resp) {
    int i = 0;
    p = decode_enc_str(msg_begin, p, resp->host);
    
    int type = (*p) * 255 + (*(p + 1));
    p += 2;
    int qclass = (*p) * 255 + (*(p + 1));
    p += 2;
    int ttl = ntohl(*(uint32_t*)p);
    p += 4;
    int rdlen = (*p) * 255 + (*(p + 1));
    p += 2;

    resp->type = type;
    
    if(type == 0x1) {
        for(i = 0; i < 4; i++) {
            snprintf(resp->ip, sizeof(resp->ip), "%d.%d.%d.%d", *p, *(p+1), *(p+2), *(p+3));
        }
        //printf("ip:%s\n", resp->ip);
    } else if(type == 0x5) {
        decode_enc_str(msg_begin, p, resp->cname);
	printf("cname:%s\n", resp->cname);
    }

    p += rdlen;

    return p;

}

static void decode_response(const char* resp, int len) {
    int i = 0;
    struct request_record* reqs = NULL;
    struct response_record* resps = NULL;
    unsigned char* p = (unsigned char*)resp;
    int id = (*p) * 255 + (*(p + 1));
    int qr = (*(p + 2)) >> 7;
    int rcode = (*(p + 3) & 0xf);
    int dcount = (*(p + 4)) * 255 + (*(p + 5));
    int answer_count = (*(p + 6)) * 255 + (*(p + 7));

    if(dcount) {
        reqs = (struct request_record*)calloc(1, sizeof(struct request_record) * dcount);
    }

    if(answer_count) {
        resps = (struct response_record*)calloc(1, sizeof(struct response_record) * answer_count);
    }
    
    // skip header
    p += 12;

    // skip request
    for(i = 0; i< dcount; i++) {
        p = decode_request_items((unsigned char*)resp, p, reqs + i);
    }

    for(i = 0; i < answer_count; i++) {
        p = decode_resopnse_item((unsigned char*)resp, p, resps + i);
    }

    if(reqs) {
        const char* host = reqs[0].host;
        struct dns_real_req* real_req = dns_real_req_find(host);

        if(real_req) {
            dns_real_req_active_and_free(real_req, resps, answer_count, rcode);
        }        
    }
    
    if(reqs) {
        free(reqs);
    }

    if(resps) {
        free(resps);
    }
}

static int dns_send_req(const char* host)
{
    unsigned char  send_buf[WORKSPACE_SIZE] = {};
    
    unsigned char *p = NULL;
    int rc;

    p = send_buf;
    p[1] = 0x1;
    p[2] = 0x1; //QR = 0, Opcode = 0, AA = 0, TC = 0, RD = 1.
    p[5] = 0x1; //QDCOUNT = 1
    p += 12;

     p = install_domain_name(p, host);
     p[1] = 0x1; // qtype=1
     p[3] = 1;
     p += 4;


    rc = sendto(s_fd, send_buf, p - send_buf, 0, (struct sockaddr *)&s_server_addr, sizeof(struct sockaddr_in));
    if(rc >= 0) {
        return 0;
    } else {
        return -1;
    }
}

static void dns_recv_cb(int fd, short what, void* args) {
    event_add(s_event, NULL);
    struct sockaddr_in server_addr = {};
    socklen_t addr_len = sizeof(struct sockaddr_in);
    

    if(what != EV_READ) {
        return;
    }
    static char recv_buf[1024] = {};
    //char* recv_buf = new char[1024];
    //bzero(recv_buf, 1024);
    int rc = recvfrom(s_fd, recv_buf, 1024, 0, (struct sockaddr *)&server_addr, &addr_len);
    if( rc == -1 ) {
        //delete recv_buf;
        return;
    }

    decode_response(recv_buf, rc);
    //delete[] recv_buf;
}

void dns_cancel_all() {
    if(s_event) {
        printf("dns cancel all\n");
        if(event_pending(s_event, EV_READ, NULL)) {
            event_del(s_event);
        }
        event_free(s_event);
        close(s_fd);
        s_base = NULL;
        s_fd = 0;
    }
    for(int i = 0; i < HASH_BUCKET_SIZE; i++) {
        dns_real_req* pos;
        dns_real_req* tmp;
        list_for_each_entry_safe(pos, tmp, &s_hash[i], list) {
            printf("start free dns\n");
            dns_real_req_active_and_free(pos, NULL, 0, -1);            
        }
    }

    for(int i = 0; i < CACHE_HASH_BUCKET_SIZE; i++) {
        cache_record* pos;
        cache_record* tmp;
        list_for_each_entry_safe(pos, tmp, &s_cache_hash[i], list) {
            list_del(&pos->list);
            free(pos);
        }
    }
}

int dns_fini() {
    return 0;
}
