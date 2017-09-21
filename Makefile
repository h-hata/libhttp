OBJ= debug.o header.o parser.o util.o http.o

http.a:$(OBJ)
	ar r  http.a $(OBJ)
.c.o:
	gcc -Wall -c $< -DDEBUG -ggdb
clean:
	rm -fr *.o http.a
