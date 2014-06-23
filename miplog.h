#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include "defines.h"

char *month_arr[12]={
"Jan","Feb","Mar","Apr","May","Jun",
"Jul","Aug","Sep","Oct","Nov","Dec"
};

char *day_arr[7]={
"Sun","Mon","Tue","Wed","Thu","Fri","Sat"
};

char *mydate(void);


char *hostlookup(unsigned long int);
char *servlookup(unsigned short);

struct ippkt_tcp
{
   struct iphdr ip;
   struct tcphdr tcp;
   char buffer[10000];
}pkt_tcp;

struct ippkt_icmp
{
   struct iphdr ip;
   struct icmphdr icmp;
   char buffer[10000];
}pkt_icmp;

struct ippkt_udp
{
   struct iphdr ip;
   struct udphdr udp;
   char buffer[10000];
}pkt_udp;

