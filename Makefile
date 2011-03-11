all: udptap

udptap: udptap.c
	$(CC) -O2 -Wall -o $@ $^ -lpcap

clean:
	rm -f udptap *~
