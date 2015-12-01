TARGET = test
DEPS = co_base.o \
	   co_socket.o \
	   co_thread.o \
	   coroutine.o \
	   main.o

STATIC = libevent/libevent.a
INCLUDE = -I./ \
	-Ilibevent/ \
	-Ilibevent/include/

CFLAGS = $(INCLUDE)
CXXFLAGS = $(INCLUDE)

$(TARGET): $(DEPS) $(STATIC)
	g++ -lrt -o $(TARGET) $(DEPS) $(STATIC)

libevent/libevent.a:
	make -C libevent

clean:
	rm -f $(TARGET) $(DEPS)
	make clean -C libevent