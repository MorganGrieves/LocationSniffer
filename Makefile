default:
	gcc -std=gnu99 -ggdb3 -o main main.c -lpcap -lcurl
	sudo ./main
