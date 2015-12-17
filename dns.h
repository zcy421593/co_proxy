#ifndef DNS_H
#define DNS_H

int dns_init(struct co_base* base, const char* ns_server);
const char* dns_resolve(const char* host);
int dns_fini();
void dns_cancel_all();
#endif

