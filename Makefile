CC=gcc
CFLAGS=-Wall -O3

SRC=src

libcollider.so: $(SRC)/libcollider.c $(SRC)/collider.h
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<

clean:
	$(RM) -rf *.so *.o *.exe