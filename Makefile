cthulhu: 
	gcc -D_GNU_SOURCE -o cthulhu cthulhu.c -lnl-3 -lnl-route-3 -lcgroup -lcap -lc -I/usr/include/libnl3

.PHONY: cthulhu
