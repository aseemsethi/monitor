#include <stdio.h>
#include <string.h>
#include "../common/parser.h"
/* somewhat unix-specific */ 
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h> // for exit
#include "../common/log.h"
#include <netinet/in.h>
#include <arpa/inet.h> // for inet_ntoa
#include <netinet/ip_icmp.h>
#include "bgp.h"

FILE *fp;
FILE *fbgpStats;

typedef struct {
    struct sockaddr_in routerID;
	int 	holdTime;
    struct sockaddr_in server_addr;
    struct sockaddr_ll sll;
    int sock;
} bgp_t;

bgp_t bgp;

sendBgpData (bgp_t *bgp, uchar *ptr, int length) {
    int sent;

    log_debug(fp, "BGP: SendData: Sending %d Bytes", length); fflush(stdout);
    sent = sendto(bgp->sock, ptr, length, 0,
            (struct sockaddr*)&bgp->server_addr, sizeof(bgp->server_addr));
    if(sent == -1) {
            perror(" - send error: ");
    } else {
            log_debug(fp, " :%d Bytes", sent);
    }
    fflush(fp);
}

putBgpHdr(char *buff, int type) {
	memset(buff, 0xff, 16);
	buff[18] = type;
}

sendOpen (bgp_t *bgp, jsonData_t* jsonData) {
	struct bgp_open open;

	memset(open.bgpo_marker, 0xFF, 16);
	open.bgpo_len = htons(29);
	open.bgpo_type = BGP_OPEN;
	open.bgpo_version = BGP_VERSION;
	open.bgpo_myas = htons(1);
	open.bgpo_holdtime = 0;

    if(inet_aton(jsonData->routerID, &bgp->routerID.sin_addr) == 0) {
		log_error(fp, "BGP: inet_aton failed");
		exit(1);
	}
	printf("\n router ID = %d", bgp->routerID.sin_addr.s_addr);
	open.bgpo_id = bgp->routerID.sin_addr.s_addr;
	open.bgpo_optlen = 0;

	sendBgpData(bgp, (uchar*)&open, 29);
}

initBgpConnection(bgp_t *bgp, jsonData_t* jsonData) {
    struct sockaddr_in;

    if((bgp->sock=socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("socket:");
            log_error(fp, "BGP ERROR: create creation socket"); fflush(fp);
            exit(1);
    }
    bgp->server_addr.sin_family = AF_INET;
    bgp->server_addr.sin_port = htons(BGP_TCP_PORT);
    if(inet_aton(jsonData->serverIP, &bgp->server_addr.sin_addr) == 0) {
            log_error(fp, "inet_aton() failed\n");
            log_error(fp, "BGP ERROR: create in inet_aton"); fflush(fp);
    }
    log_info(fp, "BGP: Connect to %s", jsonData->serverIP); fflush(fp);
    if(connect(bgp->sock, (struct sockaddr *)&bgp->server_addr,
                sizeof(struct sockaddr)) == -1) {
        log_error(fp, "BGP ERROR: create connecting to server"); fflush(fp);
        log_error(fbgpStats, "BGP ERROR: create connecting to server");
        fflush(fbgpStats);
        perror("Connect");
        exit(1);
    }
    log_info(fp, "BGP TCP connection created to %s, sock:%d",
        jsonData->serverIP, bgp->sock);
    fflush(fp);
}

void *bgpListener(bgp_t* bgp) {
	int running = 1;

	printf("\nBGP Listener: started"); fflush(stdout);
	while(running){
		struct timeval selTimeout;
		selTimeout.tv_sec = 1;       /* timeout (secs.) */
		selTimeout.tv_usec = 0;            /* 0 microseconds */
		fd_set readSet;
		FD_ZERO(&readSet);
		FD_SET(bgp->sock, &readSet);

	int numReady = select(FD_SETSIZE, &readSet, NULL, NULL, &selTimeout);
	printf(".");
	if(numReady > 0){
		if (FD_ISSET (bgp->sock, &readSet)) {
			//printf("\n BGP Data recvd...");
		}
		char buffer[100] = {'\0'};
		int bytesRead = read(bgp->sock, &buffer, sizeof(buffer));
		printf(" BytesRead %i : %s", bytesRead, buffer);
		if(bytesRead == 0) {
			running = 0;
			perror("\nBytes Read=0:");
		} else if(bytesRead < 0) {
			perror("\nBytesRead < 0, Shutdown:"); fflush(stdout);
		}
		}
	}
	printf("\nBGP Listener: stopped"); fflush(stdout);
}

int bgp_main(jsonData_t *jsonData, FILE *stats, FILE *logs) {
	pthread_t threadPID;

	fp = logs;
	fbgpStats = stats;
	log_info(fp, "\nBGP started..."); fflush(fp);

	initBgpConnection(&bgp, jsonData);
	if (pthread_create(&threadPID, NULL, bgpListener, &bgp)) {
		log_info(fp, "\nError creating BGP Listener Thread"); fflush(stdout);
		exit(1);
	}
	sendOpen(&bgp, jsonData);
	log_info(fp, "\nBGP end..."); fflush(fp);
	while (1) sleep(2);
}
