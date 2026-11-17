CC      = gcc
CFLAGS  = -O2 -Wall -Wextra -pthread $(shell pkg-config --cflags libusb-1.0)
LIBS    = $(shell pkg-config --libs libusb-1.0) -pthread

capture: capture.c
	$(CC) $(CFLAGS) -o capture capture.c $(LIBS)

clean:
	rm -f capture

.PHONY: clean
