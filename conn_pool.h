#ifndef CONN_POOL_H
#define CONN_POOL_H
#include <string>
void pool_queue_connection(struct event_base* base, std::string dest, int port, int fd);
int  pool_get_connection(std::string dest, int port);
#endif