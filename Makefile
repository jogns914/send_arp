arp:
	gcc -o arp arp.c -lnet -lpcap -lpthread
clean:
	rm -f arp
