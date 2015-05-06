AM_CFLAGS  = @libnfc_CFLAGS@

bin_PROGRAMS = mfcuk

noinst_HEADERS = crapto1.h mifare.h nfc-utils.h mfcuk_mifare.h mfcuk_finger.h mfcuk_utils.h mfcuk.h xgetopt.h

mfcuk_SOURCES = crapto1.c crypto1.c mifare.c nfc-utils.c mfcuk_mifare.c mfcuk_finger.c mfcuk_utils.c mfcuk.c
mfcuk_LDADD = @libnfc_LIBS@

# If system does not have unistd.h, use our own getopt function from xgetopt.c
if ! HAVE_UNISTD
mfcuk_SOURCES += xgetopt.c
endif

# dist_man_MANS = mfcuk.1
