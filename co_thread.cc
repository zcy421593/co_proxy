#include "co_thread.h"
#include <stdlib.h>
#include <sys/time.h>
#include "event.h"
#define MAX_WAITING_THREAD 20
struct co_thread {
	co_base* base;
	co_threadcb start_cb;
	void* start_args;
	int task_id;
	void* ret_value;
	event* tmr_start;
	event* tmr_notify_waiting;

	int waiting_thread_taskid;
	bool is_detached;
	bool is_complete;
};

static void thread_notifycb(int fd, short what, void * args) {
	co_thread* thread = (co_thread*)args;
	event_free(thread->tmr_notify_waiting);
	thread->tmr_notify_waiting = NULL;
	coroutine_resume(thread->base->sch, thread->waiting_thread_taskid);

	if(thread->is_detached){
		free(thread);
	}
}

static void thread_do_excute(schedule* sch, void* args) {
	co_thread* thread = (co_thread*)args;
	thread->ret_value = thread->start_cb(thread, thread->start_args);
	thread->is_complete = true;
	if(thread->waiting_thread_taskid >= 0) {
		timeval val = {};
		thread->tmr_notify_waiting = evtimer_new(thread->base->base, thread_notifycb, thread);
		evtimer_add(thread->tmr_notify_waiting, &val);
	} else if(thread->is_detached){
		co_thread_free(thread);
	}
}

static void thread_startcb(int fd, short what, void * args) {
	co_thread* thread = (co_thread*)args;
	event_free(thread->tmr_start);
	thread->tmr_start = NULL;
	thread->task_id = coroutine_new(thread->base->sch, thread_do_excute, thread);
	coroutine_resume(thread->base->sch, thread->task_id);
}

co_thread* co_thread_create(co_base* base, co_threadcb cb, void* args) {
	co_thread* thread = (co_thread*)calloc(1, sizeof(co_thread));
	thread->base = base;
	thread->start_args = args;
	thread->start_cb = cb;
	thread->waiting_thread_taskid = -1;
	timeval val = {};
	thread->tmr_start = evtimer_new(base->base, thread_startcb, thread);
	evtimer_add(thread->tmr_start, &val);
	return thread;
}

void* co_thread_join(co_thread* thread) {

	int current_task_id = coroutine_running(thread->base->sch);
	if(current_task_id < 0) {
		return NULL;
	}

	if(!thread->is_complete) {
		thread->waiting_thread_taskid = current_task_id;
		coroutine_yield(thread->base->sch);
	}
	
	return thread->ret_value;
}

void co_thread_free(co_thread* thread) {
	if(thread->tmr_start) {
		evtimer_del(thread->tmr_start);
		event_free(thread->tmr_start);
		thread->tmr_start = NULL;
	}

	if(thread->tmr_notify_waiting) {
		evtimer_del(thread->tmr_notify_waiting);
		event_free(thread->tmr_notify_waiting);
		thread->tmr_notify_waiting = NULL;
	}

	free(thread);
}

void co_thread_detach(co_thread* thread) {
	thread->is_detached = true;
}

void* co_thread_get_args(co_thread* thread) {
	return thread->start_args;
}

co_base* co_thread_get_base(co_thread* thread) {
	return thread->base;
}
