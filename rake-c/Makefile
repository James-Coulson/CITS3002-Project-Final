# MACROS
C11 	= cc -std=c11
CFLAGS	= -Wall -Werror -pedantic
P		= rake-c
H 		= $(P).h
OBJ		= globals.o rake-c.o utility.o parsing.o file_transmitting.o quoting.o executing.o

# COMPILES
$(P) : $(OBJ)
	$(C11) $(CFLAGS) -o rake-c $(OBJ)

rake-c.o : rake-c.c $(H) utility.c file_transmitting.c quoting.c executing.c
	$(C11) $(CFLAGS) -c rake-c.c

globals.o : globals.c $(H)
	$(C11) $(CFLAGS) -c globals.c

utility.o : utility.c $(H)
	$(C11) $(CFLAGS) -c utility.c

parsing.o : parsing.c $(H)
	$(C11) $(CFLAGS) -c parsing.c

file_transmitting.o : file_transmitting.c $(H)
	$(C11) $(CFLAGS) -c file_transmitting.c

quoting.o : quoting.c $(H)
	$(C11) $(CFLAGS) -c quoting.c

executing.o: executing.c $(H)
	$(C11) $(CFLAGS) -c executing.c
