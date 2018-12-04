all: xchange

CFLAGS += -Wall -Wextra -O3

#LDFLAGS +=

xchange: xchange.o crc32c_br.o

xchange.o: xchange.c crc32c_br.h

crc32c_br.o: crc32c_br.c crc32c_br.h


clean:
	rm xchange *.o
