all:kalyna-reference
kalyna-reference: kalyna.c kalyna.h main.c makefile tables.c tables.h transformations.h
	gcc kalyna.c main.c tables.c -o kalyna-reference
	./kalyna-reference
