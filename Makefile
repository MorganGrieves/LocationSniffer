default:
	gcc -Wall -Werror -pedantic -std=gnu99 -ggdb3 -o main main.c -lpcap -lcurl

run:
	sudo ./main
