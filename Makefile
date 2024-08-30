CC = gcc
CFLAGS = -Wall
OBJ = main.o aes.o sha256.o blowfish.o

encriptador: $(OBJ)
	$(CC) -o $@ $(OBJ)

main.o: main.c
	$(CC) $(CFLAGS) -c main.c

aes.o: aes.c
	$(CC) $(CFLAGS) -c aes.c

sha256.o: sha256.c
	$(CC) $(CFLAGS) -c sha256.c

blowfish.o: blowfish.c
	$(CC) $(CFLAGS) -c blowfish.c

clean:
	rm -f *.o encriptador
