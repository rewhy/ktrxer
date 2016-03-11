# Makefile for the application testing module
CC 	= gcc -O2
LD	= ld
INCS 	= -I. 
DEFS 	=
OBJS	= kband.o
LIBNAME	= .
CFLAGS 	= -g -Wall $(DEFS) $(INCS)
LIBS 	= -lpthread
	
#
all: kband

%.o: %.c
	@rm -f $@
	$(CC) $(CFLAGS) -c -o $@ $(INCS) $<

# compile the test application
kband: kband.o
	$(CC) $(CFLAGS) -o kband kband.o $(LIBS)
	
.PHONY : clean
clean:
	rm -f *.o urt *~

