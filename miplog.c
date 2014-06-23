#include "miplog.h"
extern int errno;

#ifndef NOFILE
#define NOFILE 1024
#endif

#if LOG_METHOD==0
	#define log(x) printf("%s %s",mydate(),x)
#elif LOG_METHOD==1
	#define log(x) 	if (!(fp=fopen(FILENAME,"a"))) { \
				printf("Error, can't open file %s\n",FILENAME);\
				exit(0);\
				} \
			fprintf(fp,"%s %s",mydate(),x); \
			fclose(fp); 
#elif LOG_METHOD==2
	#define log(x) syslog(LOG_NOTICE, x)
#elif LOG_METHOD==3
	#define log(x) 	syslog(LOG_NOTICE, x); \
			if (!(fp=fopen(FILENAME,"a"))) { \
                                printf("Error, can't open file %s\n",FILENAME);\
                                exit(0);\
                                } \
                        fprintf(fp,"%s %s",mydate(),x); \
                        fclose(fp);  
#endif

#if LOG_METHOD!=0
int go_background(void);
#endif

#if LOG_METHOD!=0
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
#endif

int main(int argc, char **argv)
{
int stcp,sicmp,sudp,high;
int i;
char tmpbuff[1024];
fd_set set;
FILE *fp;

setuid(0);
if(geteuid() != 0) {
	printf("This program requires root privledges\n");
	exit(0);
	}

#if LOG_METHOD != 0
go_background();
#endif

#if LOG_METHOD==2 || LOG_METHOD==3
   openlog("miplog", 0, LOG_DAEMON);
#endif

#ifdef FUNNY_MSG
log("**** Started MipLOG **** Kick out LaMeRs!\n");
#else
log("MipLog started...\n"); 
#endif

stcp=socket(AF_INET, SOCK_RAW, 6); /* tcp */
sicmp=socket(AF_INET, SOCK_RAW, 1); /* icmp */
sudp=socket(AF_INET, SOCK_RAW, 17); /* udp */


while(1) {

	FD_ZERO(&set);
	FD_SET(stcp,&set);
	FD_SET(sicmp,&set);
	FD_SET(sudp,&set);

	select(FD_SETSIZE, &set, 0, 0, 0);

	if (FD_ISSET(stcp,&set)) tcp_packet(stcp);
	else if (FD_ISSET(sicmp,&set)) icmp_packet(sicmp);
	else if (FD_ISSET(sudp,&set)) udp_packet(sudp);
	}

}


char *hostlookup(unsigned long int in)
{
   static char blah[1024];
   struct in_addr i;
   struct hostent *he;
         
i.s_addr=in;

   he=gethostbyaddr((char *)&i, sizeof(struct in_addr),AF_INET);
   if(he == NULL) 

     strcpy(blah, inet_ntoa(i));
    else strcpy(blah, he->h_name);
   return blah;
}
                        

char *tcpservlookup(unsigned short port)
{
   struct servent *se;
   static char buff[1024];
   
   se=getservbyport(port, "tcp");
   if(se == NULL) sprintf(buff, "%d", ntohs(port));
   else sprintf(buff, "%s", se->s_name);
   return buff;
}

char *udpservlookup(unsigned short port)
{
   struct servent *se;
   static char buff[1024];
   
   se=getservbyport(port, "udp");
   if(se == NULL) sprintf(buff, "%d", ntohs(port));
   else sprintf(buff, "%s", se->s_name);
   return buff;
}


char *mydate(void)
{
struct tm *time_struct; 
time_t unix_time;
static char date[120];
int month,day,weekday,hour,minute,sec;

time(&unix_time);
time_struct=localtime(&unix_time);

month=time_struct->tm_mon;
day=time_struct->tm_mday;
weekday=time_struct->tm_wday;
hour=time_struct->tm_hour;
minute=time_struct->tm_min;
sec=time_struct->tm_sec;

sprintf (date,"%s %s %d %02d:%02d:%02d : ",month_arr[month],day_arr[weekday],day,hour,minute,sec);

return date;

}



tcp_packet(int stcp) {
char msg[300];
FILE *fp;

read(stcp, (struct ippkt_tcp *)&pkt_tcp,9999);
if(pkt_tcp.tcp.syn == 1 && pkt_tcp.tcp.ack == 0) {

	if(ntohs(pkt_tcp.tcp.source) == 20 && ntohs(pkt_tcp.tcp.dest) < 1024) {
		sprintf(msg,"FTPBounce attack detected from %s\n",hostlookup(pkt_tcp.ip.saddr));
		log(msg);
		return;
		}

	if(ntohs(pkt_tcp.tcp.source) != 20) {

#ifdef FUNNY_MSG
		sprintf(msg,"Hey dude! Someone is knocking to our %s door from %s\n",tcpservlookup(pkt_tcp.tcp.dest),hostlookup(pkt_tcp.ip.saddr)); 
#else
		sprintf(msg,"port %s connection attempt from %s\n", tcpservlookup(pkt_tcp.tcp.dest), hostlookup(pkt_tcp.ip.saddr));
#endif
		log(msg);
		return;	
		}
	}
}



icmp_packet(int sicmp) {
char msg[300];
FILE *fp;

	read(sicmp, (struct ippkt_icmp *)&pkt_icmp, 9999);
	if(pkt_icmp.ip.ihl != 5) {
#ifdef FUNNY_MSG
		sprintf(msg,"Blearch!! What strange ip options from %s\n",hostlookup(pkt_icmp.ip.daddr));
#else
		sprintf(msg,"suspicious ip options from %s\n",hostlookup(pkt_icmp.ip.daddr));
#endif
		log(msg);
		return;
		}
	switch(pkt_icmp.icmp.type) {
		case ICMP_DEST_UNREACH :
#ifdef FUNNY_MSG
			sprintf(msg,"damn! Destination Unreachable from %s\n",hostlookup(pkt_icmp.ip.saddr));
#else
			sprintf(msg,"destination unreachable from %s\n",hostlookup(pkt_icmp.ip.saddr));
#endif
			log(msg);
			break;

		case ICMP_SOURCE_QUENCH :
			sprintf(msg,"source quench from %s\n",hostlookup(pkt_icmp.ip.saddr));
			log(msg);
			break;

		case ICMP_REDIRECT :
			sprintf(msg,"source route from %s\n",hostlookup(pkt_icmp.ip.saddr));
			log(msg);
			break;

		case ICMP_ECHO : 
#ifdef FUNNY_MSG
			sprintf(msg,"Hey dude! Someone's playing Ping-Pong from %s\n",hostlookup(pkt_icmp.ip.saddr));
#else
			sprintf(msg,"ping from %s\n",hostlookup(pkt_icmp.ip.saddr));
#endif
			log(msg);
			break;

		case ICMP_INFO_REQUEST:
			sprintf(msg,"info request from %s\n",hostlookup(pkt_icmp.ip.saddr));
			log(msg);
			break;
			}

	return;
	}

udp_packet(int sudp) {
char msg[300];
struct in_addr i;
struct hostent *he;
int j;
FILE *fp;

	read(sudp, (struct ippkt_udp *)&pkt_udp,9999);

	i.s_addr=pkt_udp.ip.saddr;

	for (j=0; j<MAX_SITES; j++) {
		if (strstr(inet_ntoa(i), sites_array[j])) return;
		}
		

#ifdef FUNNY_MSG
	sprintf(msg,"Hey dude! UDP packet to our %s door from %s\n",udpservlookup(pkt_udp.udp.dest),hostlookup(pkt_udp.ip.saddr)); 
#else
	sprintf(msg,"UDP packet for %s port from %s\n", udpservlookup(pkt_udp.udp.dest), hostlookup(pkt_udp.ip.saddr));
#endif
	log(msg);
	return;	
}



