TARGET = test
DEPS = http_parser.o \
	   utils.o \
	   co_base.o \
	   co_socket.o \
	   co_thread.o \
	   coroutine.o \
	   dns.o \
	   conn_pool.o \
	   http_upstream.o \
	   http_downstream.o \
	   main.o

STATIC = libevent/libevent.a
INCLUDE = -I./ \
	-Ilibevent/ \
	-Ilibevent/include/

CFLAGS = $(INCLUDE) -g
CXXFLAGS = $(INCLUDE) -g

$(TARGET): $(DEPS) $(STATIC)
	g++ -lrt -o $(TARGET) $(DEPS) $(STATIC)

libevent/libevent.a:
	make -C libevent

clean:
	rm -f $(TARGET) $(DEPS)
	make clean -C libevent