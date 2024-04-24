CC=clang
CFLAGS= -O3

ALL:	LYNX

LYNX:
		$(CC) $(CFLAGS) genkat_aead.c encrypt.c skinny_reference.c -o lynx

clean:
		rm -r lynx