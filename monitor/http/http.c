/*
 * Some of the code to generate the ping packets is taken from
 * https://www.cs.utah.edu.~swalton/listings/sockets/programs/part4/chap18/myping.c
 */
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include "../xmlparser/xmlparse.h"
#include "ping.h"
#include "../log.h"

FILE *fhttp;
FILE *fhttpStats;
int pingPid = -1;

void httpListener (xmlData_t* xmlData) {
	int sock;
	struct sockaddr_in addr;
	unsigned char buf[1024];
	struct protoent* proto = NULL;

	proto = getprotobyname("ICMP");
	sock = socket(PF_INET, SOCK_RAW, proto->p_proto);
	if (sock < 0) {
		perror("socket");
		exit(0);
	}
	log_debug(fping, "Entering Ping Listener Loop...");
	while(1) {
		int bytes, len = sizeof(addr);
		bzero(buf, sizeof(buf));
		bytes = recvfrom(sock, buf, sizeof(buf), 0, 
				(struct sockaddr*)&addr, &len);
		if (bytes > 0)
			display(buf, bytes, xmlData);
		else {
			perror("recvfrom");
		}
	}
	exit(0);
}

void* httpStart(void *args) {
	pthread_t threadPID;
	char filePath[100];

	xmlData_t* xmlData = (xmlData_t*)args;

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", xmlData->custID);
	sprintf(&filePath[strlen(filePath)], "/http_stats");
	fpingStats = fopen(filePath, "a");
	log_debug(fpingStats, "HTTP started: custID: %d, server:%s, serverURL:%s", 
			xmlData->custID, xmlData->serverIP, xmlData->serverURL);

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", xmlData->custID);
	sprintf(&filePath[strlen(filePath)], "/http_logs");
	fping = fopen(filePath, "a");
	log_debug(fping, "HTTP started: custID: %d, server:%s, serverURL:%s", 
			xmlData->custID, xmlData->serverIP, xmlData->serverURL);

	if (pthread_create(&threadPID, NULL, httpListener, xmlData)) {
		printf("\nError creating Listener Thread"); fflush(stdout);
		exit(1);
	}
	// TBD: For now use this to ensure that the listener runs and is 
	// waiting for pkts
	sleep(1); 

	fclose(fping);
	return 0;
}

