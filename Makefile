main : main.o aes.o tests.o encrypt.o
	gcc -g -o $@ $^

main.o : main.c all.h
	gcc -c $< -g

encrypt.o : encrypt.c all.h	
	gcc -c $< -g

tests.o : tests.c all.h	
	gcc -c $< -g

aes.o : aes.c all.h
	gcc -c $< -g
	
clean :
	rm -rf *.o
	rm -rf main
