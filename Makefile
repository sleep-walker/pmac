all: pmac

pmac: pmac.c
	gcc -Wall pmac.c -o pmac -g
