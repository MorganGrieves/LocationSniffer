default:
	gcc -std=gnu99 -g -o main main.c -lpcap -lcurl
	sudo ./main
