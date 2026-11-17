CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra
CFLAGS  += -pthread $(shell pkg-config --cflags libusb-1.0)
LIBS     = $(shell pkg-config --libs libusb-1.0) -pthread

PREFIX     ?= /usr/local
BINDIR     ?= $(PREFIX)/bin
UDEVDIR    ?= /etc/udev/rules.d
USERUNITDIR?= /etc/systemd/user
MODPROBEDIR?= /etc/modprobe.d
MODLOADDIR ?= /etc/modules-load.d
DESTDIR    ?=

capture: capture.c init_sequence.h
	$(CC) $(CFLAGS) -o capture capture.c $(LIBS)

install: capture
	install -Dm755 capture $(DESTDIR)$(BINDIR)/hd60s-capture
	install -Dm644 dist/60-elgato-hd60s.rules $(DESTDIR)$(UDEVDIR)/60-elgato-hd60s.rules
	install -d $(DESTDIR)$(USERUNITDIR)
	sed 's|@BINDIR@|$(BINDIR)|' dist/hd60s-capture.service > $(DESTDIR)$(USERUNITDIR)/hd60s-capture.service
	chmod 644 $(DESTDIR)$(USERUNITDIR)/hd60s-capture.service
	install -Dm644 dist/modprobe-hd60s.conf $(DESTDIR)$(MODPROBEDIR)/hd60s.conf
	install -Dm644 dist/modules-load-hd60s.conf $(DESTDIR)$(MODLOADDIR)/hd60s.conf
	@if [ -z "$(DESTDIR)" ]; then \
	  udevadm control --reload && udevadm trigger --subsystem-match=usb --attr-match=idVendor=0fd9 ; \
	  lsmod | grep -q '^v4l2loopback' || modprobe v4l2loopback ; \
	  echo ; echo "Installed.  Replug the card (or run: systemctl --user daemon-reload && systemctl --user start hd60s-capture)" ; \
	fi

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/hd60s-capture \
	      $(DESTDIR)$(UDEVDIR)/60-elgato-hd60s.rules \
	      $(DESTDIR)$(USERUNITDIR)/hd60s-capture.service \
	      $(DESTDIR)$(MODPROBEDIR)/hd60s.conf \
	      $(DESTDIR)$(MODLOADDIR)/hd60s.conf
	@if [ -z "$(DESTDIR)" ]; then udevadm control --reload ; fi

clean:
	rm -f capture

.PHONY: install uninstall clean
