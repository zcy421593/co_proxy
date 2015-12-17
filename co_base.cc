#include "co_base.h"
#include <stdlib.h>
#include <event.h>
co_base* co_base_create() {
	co_base* base = (co_base*)calloc(1, sizeof(co_base));
	base->base = event_base_new();
	base->sch = coroutine_open();
	return base;
}
void co_base_dispatch(co_base* base) {
	event_base_dispatch(base->base);
	printf("event base dispatch complete\n");
	event_base_free(base->base);
	coroutine_close(base->sch);
}
