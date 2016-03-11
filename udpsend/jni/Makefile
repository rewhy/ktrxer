# Makefile for the application testing module
CC 	= gcc #arm-linux-androideabi-gcc -O2
LD	= ld
INCS 	= -I. 
DEFS 	=
OBJS	= udpsocket.o
LIBNAME	= .
CFLAGS 	= -g -Wall $(DEFS) $(INCS)
LIBS 	= .
	
#
all: udpsocket

%.o: %.c
	@rm -f $@
	$(CC) $(CFLAGS) -c -o $@ $(INCS) $<

# compile the test application
udpsocket: udpsocket.o
	$(CC) $(CFLAGS) -o udpsocket udpsocket.o

	
.PHONY : clean
clean:
	rm -f *.o udpsocket pcapture *~
