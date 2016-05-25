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
#include <fcntl.h>
#include <errno.h>

FILE *fp;
FILE *fbgpStats;

typedef struct {
	jsonData_t *jsonData;
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
            //log_debug(fp, " :%d Bytes", sent);
    }
    fflush(fp);
}

putBgpHdr(char *buff, int type) {
	memset(buff, 0xff, 16);
	buff[18] = type;
}

sendKeepalive (bgp_t *bgp) {
	struct bgp_open open;

	log_info(fp, "BGP: Send KEEPALIVE"); fflush(stdout);
	memset(open.bgpo_marker, 0xFF, 16);
	open.bgpo_len = htons(19);
	open.bgpo_type = BGP_KEEPALIVE;

	sendBgpData(bgp, (uchar*)&open, 19);
}

sendOpen (bgp_t *bgp) {
	struct bgp_open open;
	int i;
	jsonData_t *jsonData = bgp->jsonData;

	log_info(fp, "BGP: Send OPEN"); fflush(stdout);
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
	log_info(fp, "BGP self router ID = %x", bgp->routerID.sin_addr.s_addr);
	open.bgpo_id = bgp->routerID.sin_addr.s_addr;
	open.bgpo_optlen = 0;

	for (i=0;i<29;i++)
		printf(" %2X", ((uchar*)&open)[i]);
	sendBgpData(bgp, (uchar*)&open, 29);
}

bgpExecTests(bgp_t *bgp) {
	jsonData_t *jsonData = bgp->jsonData;
	int i;

	sleep(1);
	// Send Update Message
	printf("\n Withdran len = %d", jsonData->withdrawnLen);
	for(i=0;i<jsonData->wIndex;i++) {
		printf("\n Withdran prefix:%d, route:%s", 
			jsonData->withdrawnPrefix[i], jsonData->withdrawnRoute);
	}
	printf("\n Path Attr len = %d", jsonData->pathAttrLen);
	for(i=0;i<jsonData->pathIndex;i++) {
		printf("\n Path Attributes: Flag:%d, Type:%d, Len:%d",
			jsonData->pathFlag[i], jsonData->pathType[i], jsonData->pathLen[i]);
	}
	printf("\n NLRI len = %d, prefix:%s",
			jsonData->nlriLen, jsonData->nlriPrefix);
	fflush(stdout);
}

initBgpConnection(bgp_t *bgp, jsonData_t* jsonData) {
    struct sockaddr_in;
	int arg, err;

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
	// Set non-blocking 
	if( (arg = fcntl(bgp->sock, F_GETFL, NULL)) < 0) { 
		perror("F_GETFL:");
		exit(0); 
	} 
	arg |= O_NONBLOCK; 
	if( fcntl(bgp->sock, F_SETFL, arg) < 0) { 
		perror("F_SETFL:");
		exit(0); 
	} 
    err = connect(bgp->sock, (struct sockaddr *)&bgp->server_addr,
                sizeof(struct sockaddr));
	if (errno != EINPROGRESS) {
		// Note: connect on blocking socket returns EINPROGRESS
        log_error(fp, "BGP ERROR: create connecting to server"); fflush(fp);
        log_error(fbgpStats, "BGP ERROR: create connecting to server");
        fflush(fbgpStats);
        perror("Connect Error:");
        exit(1);
    } else {
		/* struct timeval stTv;
		fd_set write_fd; stTv.tv_sec = 20; stTv.tv_usec = 0;
        FD_ZERO(&write_fd); FD_SET(bgp->sock,&write_fd);
        select((bgp->sock+1), NULL, &write_fd, NULL, &stTv);
		*/
//http://stackoverflow.com/questions/10187347/async-connect-and-disconnect-with-epoll-linux/10194883#10194883
		int result;
		socklen_t result_len = sizeof(result);
		if (getsockopt(bgp->sock, SOL_SOCKET, SO_ERROR, 
				&result, &result_len) < 0) {
			// error, fail somehow, close socket
			return;
		}
		if (result != 0) {
			// connection failed; error code is in 'result'
			return;
		}
		// socket is ready for read()/write()
		//log_info(fp, "TCP Connected.."); fflush(fp);
	}
    log_info(fp, "BGP TCP connection created to %s, sock:%d",
        jsonData->serverIP, bgp->sock);
    fflush(fp);
}

void *bgpListener(bgp_t* bgp) {
	int running = 1;


	log_info(fp, "BGP Listener: started"); fflush(fp);
	while(running){
		struct timeval selTimeout;
		selTimeout.tv_sec = 5;       /* timeout (secs.) */
		selTimeout.tv_usec = 0;
		fd_set readSet;
		FD_ZERO(&readSet);
		FD_SET(bgp->sock, &readSet);

		int numReady = select(FD_SETSIZE, &readSet, NULL, NULL, &selTimeout);
		if(numReady > 0){
			if (FD_ISSET (bgp->sock, &readSet)) {
				//printf("\n BGP Data recvd...");
			}
			char buffer[100] = {'\0'};
			int i;
			int bytesRead = read(bgp->sock, &buffer, sizeof(buffer));
			if(bytesRead < 0) {
				perror("\nBytesRead < 0, Shutdown:"); fflush(stdout);
				running = 0;
			} else if (bytesRead == 0) {
			// TBD: For some reason, the select returns immediately and 
			// ignores the timeout, even though the sock is in NONBLOCK
			// mode. For now, ignoring this and continuing.
				continue;
			}
			printf("\nBytesRead %i", bytesRead);
			for (i=0;i<bytesRead;i++)
				printf(" %2X", buffer[i]);
			fflush(stdout);
			if (memcmp(buffer, "1111111111111111", 16) == 0) {
				printf("\nBGP Marker recvd correctly");
			} 
			switch (buffer[18]) {
				case 1: log_info(fp, "OPEN recvd"); 
						sendOpen(bgp);
						sendKeepalive(bgp); 
						break;
				case 2: log_info(fp, "UPDATE recvd"); break;
				case 3: log_info(fp, "NOTIFICATION recvd"); break;
				case 4: log_info(fp, "KEEPALIVE recvd"); break;
				default: log_info(fp, "Unknown BGP Type recvd");
			}
			fflush(fp);
		}
	}
	log_error(fp, "\nBGP Listener: stopped"); fflush(stdout);
}

int bgp_main(jsonData_t *jsonData, FILE *stats, FILE *logs) {
	pthread_t threadPID;

	fp = logs;
	fbgpStats = stats;
	log_info(fp, "BGP started..."); fflush(fp);

	bgp.jsonData = jsonData;
	initBgpConnection(&bgp, jsonData);
	if (pthread_create(&threadPID, NULL, bgpListener, &bgp)) {
		log_info(fp, "Error creating BGP Listener Thread"); fflush(stdout);
		exit(1);
	}
	bgpExecTests(&bgp);
	while (1) sleep(2);
}
