bin_PROGRAMS = mfcuk_keyrecovery_darkside

noinst_HEADERS = \
		 crapto1.h \
		 mfcuk_finger.h \
		 mfcuk_keyrecovery_darkside.h \
		 mfcuk_mifare.h \
		 mfcuk_utils.h \
		 mifare.h \
		 nfc-utils.h \
		 xgetopt.h

# set the include path found by configure
mfcuk_keyrecovery_darkside_SOURCES = 	\
					crapto1.c \
					crypto1.c \
					mfcuk_finger.c \
					mfcuk_keyrecovery_darkside.c \
					mfcuk_mifare.c \
					mfcuk_utils.c \
					mifare.c \
					nfc-utils.c

mfcuk_keyrecovery_darkside_LDADD = -lnfc -lusb -lpcsclite

# dist_man_MANS = mfcuk_keyrecovery_darkside.1
