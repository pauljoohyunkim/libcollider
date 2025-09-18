CC=gcc
CFLAGS=-Wall -O3

SRC=src

libcollider.so: $(SRC)/libcollider.c $(SRC)/collider.h
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@

libcollider.o: $(SRC)/libcollider.c $(SRC)/collider.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) -rf *.so *.o *.exe