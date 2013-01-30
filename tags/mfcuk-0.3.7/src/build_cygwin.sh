MAIN_FILE=mfcuk_keyrecovery_darkside
LIBNFC=libnfc
CFLAGS=`pkg-config --cflags ${LIBNFC}`
CFLAGS_LIBNFC=`pkg-config --cflags libnfc | cut -d ' ' -f 1`/${LIBNFC}

gcc ./${MAIN_FILE}.c ./mfcuk_mifare.c ./mfcuk_utils.c ./mfcuk_finger.c ./crapto1.c ./crypto1.c ./bin/libnfc.lib ${CFLAGS} ${CFLAGS_LIBNFC} -o ./bin/${MAIN_FILE}_cygwin.exe
