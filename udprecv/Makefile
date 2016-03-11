# Makefile for the application testing module
CC 	= gcc #arm-linux-androideabi-gcc -O2
LD	= ld
INCS 	= -I. 
DEFS 	=
OBJS	= rawsocket.o
LIBNAME	= .
CFLAGS 	= -g -Wall $(DEFS) $(INCS)
LIBS 	= .
	
#
all: rawtest

%.o: %.c
	@rm -f $@
	$(CC) $(CFLAGS) -c -o $@ $(INCS) $<

# compile the test application
rawtest: rawsocket.o
	$(CC) $(CFLAGS) -o rawtest rawsocket.o

	
.PHONY : clean
clean:
	rm -f *.o rawtest pcapture *~
