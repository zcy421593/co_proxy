#include "conn_pool.h"
#include "utils.h"

#include <event.h>
#include <vector>
#include <map>
#include <unistd.h>
using namespace std;

struct conn_info {
	string tag;
	int fd;
	event* ev;
};
static map<string, conn_info*> s_map;

static void event_cb(int fd, short what, void* args) {
	conn_info* info = (conn_info*)args;
	if(s_map.find(info->tag) != s_map.end()) {
		s_map.erase(info->tag);
	}
	
	event_free(info->ev);
	close(info->fd);
	delete info;
} 

void pool_queue_connection(event_base* base, std::string dest, int port, int fd) {
	string tag = get_format_string("%s:%d", dest.c_str(), port);
	conn_info* conn = new conn_info;
	conn->fd = fd;
	conn->tag = tag;
	if(s_map.find(tag) == s_map.end()) {
		s_map[tag] = conn;
		conn->ev = event_new(base, fd, EV_READ, NULL, conn);
	}
}
int  pool_get_connection(std::string dest, int port) {
	string tag = get_format_string("%s:%d", dest.c_str(), port);
	if(s_map.find(tag) != s_map.end()) {
		conn_info* info = s_map[tag];
		event_free(info->ev);
		int tmp = info->fd;
		s_map.erase(info->tag);
		delete info;

		return tmp;
	}
	return -1;
}