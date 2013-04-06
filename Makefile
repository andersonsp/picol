APP_NAME=picol

CC = gcc

CFLAGS	= -Wall -O2 -I..

OBJS	= main.o picol.o

all : 	picol

picol: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(APP_NAME) $(LDFLAGS)

clean:
	rm -f *.o $(APP_NAME)

.PHONY: all picol clean
