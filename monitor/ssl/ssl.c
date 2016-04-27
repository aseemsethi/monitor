#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h> // for inet_ntoa
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include "../xmlparser/xmlparse.h"
#include "util.h"
#include "ssl.h"
#include "../common/log.h"

sslStruct sslP;
param_t param;
FILE *fp;

sendData(sslStruct *sslP, uchar *ptr, int length) {
    int sent;

    log_debug(fp, "SSL: SendData: Sending %d Bytes", length); fflush(stdout);
    sent = sendto(sslP->sock, ptr, length, 0,
            (struct sockaddr*)&sslP->server_addr, sizeof(sslP->server_addr));
    if(sent == -1) {
            perror(" - send error: ");
    } else {
            log_debug(fp, " :%d Bytes", sent);
    }
    fflush(fp);
}

/*
 *  * Set up a INET socket and connect to SERVER on SSL_PORT
 *   * SSL_PORT = 443 for real SSL servers
 *    */
initConnectionToServer(sslStruct *sslP, xmlData_t* xmlData) {
    struct sockaddr_in;

    if((sslP->sock=socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("socket:");
			log_error(fp, "SSL ERROR: create creation socket"); fflush(fp);
            exit(1);
    }
    sslP->server_addr.sin_family = AF_INET;
    sslP->server_addr.sin_port = htons(xmlData->sslPort);
    if(inet_aton(xmlData->serverIP, &sslP->server_addr.sin_addr) == 0) {
            printf("inet_aton() failed\n");
			log_error(fp, "SSL ERROR: create in inet_aton"); fflush(fp);
    }
	log_info(fp, "SSL: Connect to %s", xmlData->serverIP);
    if(connect(sslP->sock, (struct sockaddr *)&sslP->server_addr,
                sizeof(struct sockaddr)) == -1) {
		log_error(fp, "SSL ERROR: create connecting to server"); fflush(fp);
		log_error(sslP->fsslStats, "SSL ERROR: create connecting to server");
		fflush(sslP->fsslStats); 
        perror("Connect");
        exit(1);
    }
    log_info(fp, "TCP connection created to %s, sock:%d", 
		xmlData->serverIP, sslP->sock);
	fflush(stdout);
}

int getSelfIP() {
	int fd, status;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		log_error(fp, "ERROR: create scck for interface IP"); fflush(fp);
		return -1;
	}
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ-1);
	if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
		perror("\nioctl failure");
		return -1;
	}
	close(fd);

	sprintf(sslP.selfIP, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	log_info(fp, "SSL: SelfIP: %s", sslP.selfIP);
	fflush(fp);

	return 0;
}

/*
 * This is the start of the recvThread. Runs parallel to the main thread
 * Never returns
 * Stays in a select loop
 * 	Receives packets from network
 * 	Invokes the sslFSM[state][event]
 */
void* recvFunction(void *arg) {
	sslStruct *sslP = (sslStruct*)arg;
	uchar buff[5000];  // uchar is important
	int bytes_recv, index, i;
	int set = 0;
	int remBytes = 0;
	ushort RecordHdrLengthRecvd = 0;
	FILE *fp = sslP->fp;

	/* Notes on SSL Length
 	 * 1st Byte      2nd Byte    3rd Byte 
 	 * # S Length    Length      Padding Length
 	 * # - number of bytes in header. 0 indicates 3 byte hdr. 1 a 2 byte header
 	 * S - security escape, not implemented 
 	 * Example: For "Certificate" pkt sent by Server:
 	 * Outer Hdr Len: 12 91
 	 * Inner Hdr Len: 00 12 8d
 	 */

	log_info(fp, "SSL: recvFunction thread created"); fflush(fp);
	while(1) {
		bytes_recv = recv(sslP->sock,&buff[0], 5, MSG_PEEK);
		//log_debug(fp, " bytes_recv = %d, ", bytes_recv);
        if (bytes_recv == -1) { perror("-1: Error during recv: "); exit(1); }
        if (bytes_recv == 0) { 
				log_error(fp, "SSL: Error: recvFunction: sock closed in recv, bytes_Recv = 0"); fflush(fp);
				sleep(10); // This is so that sslTestsExec has time 
							//to gather stats
				exit(1); // No point keeping this since the sock is gone
		}
		switch(buff[0]) {
		case change_cipher_spec:
                log_info(fp, "	<- SSL: Change Cipher"); break;
		case alert:
                log_info(fp, "	<- SSL: Alert"); break;
		case handshake:
                log_info(fp, "	<- SSL: Handshake"); break;
		case application_data:
                log_info(fp, "	<- SSL: App data"); break;
		default:
                printf("	<- SSL: Error pkt recvd: %d, ", buff[0]);
				// We have some junk data. Throw it away
	 		   i=recv(sslP->sock,&buff[0],5000, 0);
				log_info(fp, "..discarding %d len data\n", i); continue;
		}
        log_info(fp, "  Version: %d, %d", buff[1], buff[2]);
	    sslP->paramP->versionResp[0] = buff[1];
       	sslP->paramP->versionResp[1] = buff[2];
		buff[3] = buff[3] & 0x7F; // clears the MSB # flag in MSByte
        RecordHdrLengthRecvd = GET_BE16(&buff[3]);
        //printf("  Record Hdr Length: %d", RecordHdrLengthRecvd);
		i=recv(sslP->sock,&buff[0],
				RecordHdrLengthRecvd+RECORD_HDR_LEN,MSG_WAITALL);
        //printf("  recvd %d\n", i);
		index = RECORD_HDR_LEN;

		if (buff[0] == change_cipher_spec) { continue; }
		if (buff[0] == alert) { continue; }

		sslP->paramP->buff = &buff[index];
		sslP->paramP->buffLen = RecordHdrLengthRecvd;
		switch(buff[index]) {
        case hello_request:
                log_info(fp, "  	<- Handshake Type: Hello Request"); break;
        case client_hello:
                log_info(fp, "  	<- Handshake Type: Client Hello"); break;
        case server_hello:
                log_info(fp, "  	<- Handshake Type:  Server Hello");
                set = 0x01<<(server_hello);
                sslP->paramP->handshakeResp |= set;
				//fsmExecute(sslP->param, SERVER_HELLO);
				break;
        case certificate:
                log_info(fp, "  	<- Handshake Type: Certificate");
                set = 0x01<<(certificate);
                sslP->paramP->handshakeResp |= set;
				//fsmExecute(sslP->param, CERTIFICATE);
                break;
        case server_key_exchange:
                log_info(fp, "  	<- Handshake Type: Server Key Exchange");
                set = 0x01<<(server_key_exchange);
                sslP->paramP->handshakeResp |= set;
                break;
        case certificate_request:
                log_info(fp, "  	<- Handshake Type: Certificate Request");
                set = 0x01<<(certificate_request);
                sslP->paramP->handshakeResp |= set;
                break;
        case server_hello_done:
                log_info(fp, "  	<- Handshake Type:  Server Hello Done");
                set = 0x01<<(server_hello_done);
                sslP->paramP->handshakeResp |= set;
				//fsmExecute(sslP->param, SERVER_HELLO_DONE);
                break;
        case certificate_verify:
                log_info(fp, "  	<- Handshake Type: Certificate Verify"); break;
                break;
        case client_key_exchange:
                log_info(fp, "  	<- Handshake Type: Client Key Exchange"); break;
                break;
        case finished:
                log_info(fp, "  	<- Handshake Type: Finished");
                set = 0x01<<(finished);
                sslP->paramP->handshakeResp |= set;
                break;
		default:
                log_info(fp, "  		<- Handshake Type: Unknown");
		} // end switch()
		fflush(fp);
	}

}

void* sslStart(void *args) {
	xmlData_t* xmlData = (xmlData_t*)args;
	char filePath[100];

	if (pthread_mutex_init(&sslP.lock, NULL) != 0) {
		printf("\nMutex init failed\n");
		perror("SSL Error:");
		fflush(stdout);
		return 0;
	} 
	// ssl_logs
	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", xmlData->custID);
	sprintf(&filePath[strlen(filePath)], "/ssl_logs");
	fp = fopen(filePath, "a");

	// ssl_stats
	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", xmlData->custID);
	sprintf(&filePath[strlen(filePath)], "/ssl_stats");
	sslP.fsslStats = fopen(filePath, "a");

	fprintf(fp, "\nSSL started"); fflush(fp);
    getSelfIP();
	sslP.paramP = &param;
	sslP.fp = fp;
	sslTestsExec(&sslP, xmlData);

	while(1) {
		sleep(2);
		continue;
	}
	fclose(fp);
	fflush(stdout);
	return 0;
}
