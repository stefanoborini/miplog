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
#include <netinet/ip.h>
#include <netinet/tcp.h>

/*
#include <linux/ip.h>
#include <linux/tcp.h>
*/
extern int errno;

#ifndef NOFILE
#define NOFILE 1024
#endif

int go_background(void);
char *hostlookup(unsigned long int);
char *servlookup(unsigned short);

struct ippkt
{
   struct iphdr ip;
   struct tcphdr tcp;
   char buffer[10000];
}pkt;

int go_background(void)
{
   int fd;
   int fs;
   
   if(getppid() != 1)
   {
      signal(SIGTTOU, SIG_IGN);
      signal(SIGTTIN, SIG_IGN);
      signal(SIGTSTP, SIG_IGN);
      fs=fork();
      if(fs < 0)
      {
         perror("fork");
         exit(1);
      }
      if(fs > 0) exit(0);
      setpgrp();
      fd=open("/dev/tty", O_RDWR);
      if(fd >= 0)
      {
         ioctl(fd, TIOCNOTTY, (char *)NULL);
         close(fd);
      }
   }
   for(fd=0;fd < NOFILE;fd++) close(fd);
   errno=0;
   chdir("/");
   umask(0);
}
               
int main(void)
{
   int s;
   int i;
   char tmpbuff[1024];

   setuid(0);   
   if(geteuid() != 0)
   {
      printf("This program requires root privledges\n");
      exit(0);
   }
   go_background();
   s=socket(AF_INET, SOCK_RAW, 6);
   openlog("tcplog", 0, LOG_DAEMON);
   
   while(1)
   {
      read(s, (struct ippkt *)&pkt, 9999);
      if(pkt.tcp.syn == 1 && pkt.tcp.ack == 0)
      {
         if(ntohs(pkt.tcp.source) == 20 && ntohs(pkt.tcp.dest) < 1024)
         {
            syslog(LOG_NOTICE, "FTPBounce attack detected from %s", hostlookup(pkt.ip.saddr));
            continue;
         }
         if(ntohs(pkt.tcp.source) != 20) syslog(LOG_NOTICE, "%s connection attempt from %s", servlookup(pkt.tcp.dest), hostlookup(pkt.ip.saddr));
      }
   }
}         

char *hostlookup(unsigned long int in)
{
   static char blah[1024];
   struct in_addr i;
   struct hostent *he;
         
   i.s_addr=in;
   he=gethostbyaddr((char *)&i, sizeof(struct in_addr),AF_INET);
   if(he == NULL) strcpy(blah, inet_ntoa(i));
   else strcpy(blah, he->h_name);
   return blah;
}
                        

char *servlookup(unsigned short port)
{
   struct servent *se;
   static char buff[1024];
   
   se=getservbyport(port, "tcp");
   if(se == NULL) sprintf(buff, "port %d", ntohs(port));
   else sprintf(buff, "%s", se->s_name);
   return buff;
}

