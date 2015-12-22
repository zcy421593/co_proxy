#ifndef CO_BASE_H
#define CO_BASE_H
#include <event.h>
#include "coroutine.h"
struct co_base {
	event_base* base;
	schedule* sch;
};

struct co_base* co_base_create();
void co_base_dispatch(co_base* base);

#endif
