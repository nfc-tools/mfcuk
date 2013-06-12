AM_CFLAGS  = @libnfc_CFLAGS@

bin_PROGRAMS = mfcuk

noinst_HEADERS = crapto1.h mifare.h nfc-utils.h mfcuk_mifare.h mfcuk_finger.h mfcuk_utils.h xgetopt.h mfcuk.h

mfcuk_SOURCES = crapto1.c crypto1.c mifare.c nfc-utils.c mfcuk_mifare.c mfcuk_finger.c mfcuk_utils.c xgetopt.c mfcuk.c 
mfcuk_LDADD = @libnfc_LIBS@

# dist_man_MANS = mfcuk.1
