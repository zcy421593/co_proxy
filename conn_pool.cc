#include "conn_pool.h"
#include "utils.h"

#include <event.h>
#include <vector>
#include <map>
#include <unistd.h>
#include <stdlib.h>
#include "list.h"
using namespace std;

struct fd_info {
	event* ev;
	list_head list;
	int fd;
};

struct conn_info {
	string tag;
	list_head list_fd;
	
};
static map<string, conn_info*> s_map;

static void event_cb(int fd, short what, void* args) {
	fd_info* info = (fd_info*)args;
	list_del(&info->list);
	event_free(info->ev);
	close(info->fd);
	free(info);
} 

void pool_queue_connection(event_base* base, std::string dest, int port, int fd) {
	string tag = get_format_string("%s:%d", dest.c_str(), port);
	conn_info* conn = NULL;
	fd_info* info = (fd_info*)calloc(1, sizeof(fd_info));
	info->fd = fd;
	info->ev = event_new(base, fd, EV_READ, event_cb, info);
	event_add(info->ev, NULL);
	if(s_map.find(tag) == s_map.end()) {
		conn = new conn_info;
		conn->tag = tag;
		conn->list_fd.next = &conn->list_fd;
		conn->list_fd.prev = &conn->list_fd;
		s_map[tag] = conn;		
	} else {
		conn = s_map[tag];
	}
	list_add(&info->list, &conn->list_fd);
}

int  pool_get_connection(std::string dest, int port) {
	string tag = get_format_string("%s:%d", dest.c_str(), port);
	int ret = -1;
	if(s_map.find(tag) != s_map.end()) {
		conn_info* conn = s_map[tag];
		if(!list_empty(&conn->list_fd)) {
			printf("reuse conn:%s\n", tag.c_str());
			fd_info* info;
			fd_info* tmp;
			list_for_each_entry_safe(info, tmp, &conn->list_fd, list) {
				ret = info->fd;
				list_del(&info->list);
				event_del(info->ev);
				event_free(info->ev);
				free(info);
				break;
			}
			
		} else {
			s_map.erase(tag);
			delete conn;
		}
	}
	return ret;
}