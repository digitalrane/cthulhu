# required libcgroup-dev, libcap-dev, libnl-3-dev and libnl-3-route-dev as well as a c compiler
gcc -D_GNU_SOURCE -o cthulhu cthulhu.c -lnl-3 -lnl-route-3 -lcgroup -lcap -lc -I/usr/include/libnl3
