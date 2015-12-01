#ifndef CO_THREAD_H
#define CO_THREAD_H
#include "co_base.h"

struct co_thread;
typedef void* (*co_threadcb)(co_thread* thread, void* args);
co_thread* co_thread_create(co_base* base, co_threadcb cb, void* args);
co_base* co_thread_get_base(co_thread* thread);
void co_thread_detach(co_thread* thread);
void* co_thread_get_args(co_thread* thread);
void* co_thread_join(co_thread* thread);
#endif
