CC=g++

CFLAGS=-c -Wall

LDFLAGS=

SOURCES := $(wildcard *.cpp)

ALLSOURCES := $(wildcard *.cpp) $(wildcard *.h)

OBJECTS=$(SOURCES:.cpp=.o)

EXECUTABLE=execFile

all:$(EXECUTABLE)

debug:CFLAGS+= -DDEBUG -g
debug:$(EXECUTABLE)

debugNoOpt:CFLAGS+= -DDEBUG -g -O0
debugNoOpt:$(EXECUTABLE)

ASAN: CFLAGS+= -DDEBUG -g -fsanitize=address -O0
ASAN: LDFLAGS+= -fsanitize=address
ASAN:$(EXECUTABLE)

$(EXECUTABLE):$(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@
	
clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
