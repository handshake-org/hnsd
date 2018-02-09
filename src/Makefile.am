AUTOMAKE_OPTIONS = foreign
SUBDIRS = c-ares

CFLAGS = -Wall -std=gnu11 -O2
LDFLAGS =

LDADD = ./c-ares/.libs/libcares.a
AM_CFLAGS = -Ic-ares

bin_PROGRAMS = hsk
hsk_SOURCES = b64.c blake2b.c cuckoo.c dns.c proof.c record.c siphash.c main.c
