/*
 * OpenVPN Tool
 */
#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include "../common/parser.h"
#include "../common/log.h"
#include "../common/util.h"
#include "openvpn.h"
#include <openssl/ssl.h>

FILE *fp;
FILE *fovStats;
ovStruct_t ovS;

/*
 * --tls-auth is read in do_init_crypto_tls_c1() in src/vpn/init.c
 * by calling get_tls_handshake_key()
 * init_key_ctx()
 */
openvpn_encrypt(ovStruct_t *ovP, uchar *ptr, int length, int hmac_index) {
	uchar tmpPtr[512];
	int tmpLen, i;
	//unsigned char hash[SHA_DIGEST_LENGTH];
	uchar *hash;
	uchar key[] = "d8cb7f984684431f75f8895e244de77dea3a5c4e559b217a39a1c4d7e0235a50dac091004acba188cc20796545db389983f8e156e064f82c9e30c1961472474c25211f2f4e2a500d133f19e24cd5f506c0a7e6f088d620d3df2ab208800c6ad64015aebf304d6b01bbf9f5e6333aace1e1fcff34545cf46044e2e33b7110da8db36b0ba225c289ad790477dcaeb3fc27e1c2f498912403dc661921eef9fd47bed857e6eba6d531381c35dcaffbf901db5ceb0d1db9454026df49f21470319a66ac3c20bbb7548d9a8d9c9fdd76de221425fccc078521735a88d5f04c9d62d03382e280ece65d1179694d5efeca1b55c1ccd42367c3f1cac4df452028a925c2d3";

	memcpy(tmpPtr, ptr, length);
	memcpy(&tmpPtr[20], &tmpPtr[0], 9);
	tmpLen = length-20;
	printf("\nopenvpn_encrypt: HMAC at:%d in pkt of len:%d, newlen:%d",
			hmac_index, length, tmpLen);
	
	// SHA1(&tmpPtr[20], tmpLen, hash);
	// hash now contains the 20-byte SHA-1 hash
	hash = HMAC(EVP_sha1(), key, strlen(key), &tmpPtr[20], tmpLen, NULL, NULL);
	memcpy(&ptr[hmac_index], hash, SHA_DIGEST_LENGTH);
	for (i=0;i<tmpLen;i++)
		printf("%2x ",tmpPtr[20+i]);
}

void ovDisplay (void *buf, int bytes, jsonData_t* jsonData) {
    int i;
    struct iphdr *ip = buf;
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip->saddr, src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->daddr, dst, INET_ADDRSTRLEN);
    i = inet_ntoa(ip->daddr);
#ifdef DEBUG
    for (i=0;i<bytes; i++) {
        if (!(i&15)) log_debug(fp, "%2X: ", i);
        log_debug(fp, "%2X ", ((unsigned char*)buf)[i]);
    }
#endif
    log_info(fp, "IPv%d:hdr-size=%d pkt-size=%d protocol=%d TTL=%d",
    ip->version, (ip->ihl)*4, ntohs(ip->tot_len), ip->protocol, ip->ttl);
    log_info(fp, "src: %s, dst: %s", src, dst);

    fflush(fp);
}

void ovListener (jsonData_t* jsonData) {
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
	log_debug(fp, "Entering OpenVPN Listener Loop...");
	while(1) {
		int bytes, len = sizeof(addr);
		bzero(buf, sizeof(buf));
		bytes = recvfrom(sock, buf, sizeof(buf), 0, 
				(struct sockaddr*)&addr, &len);
		if (bytes > 0)
			ovDisplay(buf, bytes, jsonData);
		else {
			perror("recvfrom");
		}
	}
	exit(0);
}

ovUDPSend(ovStruct_t *ovP, uchar *ptr, int length) {
	int sent, i;
	printf("\novUDPSend: %d to sock:%d", length, ovP->sock);
	fflush(stdout);
	sent = sendto(ovP->sock, ptr, length, 0, 
		(struct sockaddr *)&ovP->server_addr, sizeof(ovP->server_addr));
	if(sent < 0) {
		perror("sendto failed"); return 0;
	}
    log_info(fp, "ovUDPSend sent %d Bytes", sent); fflush(fp);
}

int initConnectionToServerOV(ovStruct_t *ovP, jsonData_t* jsonData) {
    struct sockaddr_in server_addr;
	int sock;

    if((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
            perror("socket:");
            log_error(fp, "OPENVPN ERROR: create creation socket"); fflush(fp);
            exit(1);
    }
    ovP->server_addr.sin_family = AF_INET;
    ovP->server_addr.sin_port = htons(1194);
    if(inet_aton(jsonData->serverIP, &ovP->server_addr.sin_addr) == 0) {
            log_error(fp, "inet_aton() failed\n");
            log_error(fp, "OPENVPNSSL ERROR: create in inet_aton"); fflush(fp);
    }
    log_info(fp, "OPENVPN: UDP Connected to %s:%d at sock:%d",
		jsonData->serverIP, 1194, sock);
	fflush(fp);
	return sock;
}

sendHardReset(ovStruct_t *ovP, jsonData_t *jsonData) {
	char buff[1024];
    struct timeval tv;
    time_t curtime;
	int i, index, hmac_index;
	int tlsAuth = 1;
	
    gettimeofday(&tv, NULL);
    curtime=tv.tv_sec;
	// Pkt type - 1 byte P_CONTROL_HARD_RESET_CLIENT_V2
	buff[0] = 0x38;
	// session id - 8 bytes
    PUT_BE32(&buff[1], 0);
    PUT_BE32(&buff[5], 1);
	index = 9;
	// Put the Overall seq number for replay protection and timestamp
	// only if tlsAuth is enabled for this client.
	if (tlsAuth == 1) {
		// HMAC - 20 bytes
		hmac_index=index;
		for (i=0;i<20;i++)
			buff[index+i] = 0x0;
		index += 20;
		// Packet ID = 1
    	PUT_BE32(&buff[index], 1);
		index += 4;
		// Time Stamp - not needed in case of TLS - but, we put this 
		// for initial pkts
    	PUT_BE32(&buff[index], curtime);
		index += 4;
	}
	// ACK + ACK Buffer = 0;
	buff[index] = 0x0; index+=1;
	/* Note that we do not put any 4 byte seq id, if the ACK shows 0 bytes 
	for (i=0;i<4;i++)
		buff[index+i] = 0x0;
	index+=4;
	 */
	PUT_BE32(&buff[index], ovP->seqNo);
	index +=4;
	openvpn_encrypt(ovP, buff, index, hmac_index);
	ovUDPSend(ovP, buff, index);
}

void ovExec(jsonData_t* jsonData) {
	ovStruct_t *ovP = &ovS;
	ovP->seqNo = 0;

	ovP->sock = initConnectionToServerOV(ovP, jsonData); 
	sendHardReset(ovP, jsonData);
}

void* ovStart(void *args) {
	pthread_t threadPID;
	char filePath[100];

	jsonData_t* jsonData = (jsonData_t*)args;

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/ov_stats");
	fovStats = fopen(filePath, "a");
	log_info(fovStats, "OpenVPN started: custID: %d, server:%s", 
			jsonData->custID, jsonData->serverIP);

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], "%d", jsonData->custID);
	sprintf(&filePath[strlen(filePath)], "/ov_logs");
	fp = fopen(filePath, "a");
	log_info(fp, "OpenVPN started: custID: %d, server:%s", 
			jsonData->custID, jsonData->serverIP);

	if (pthread_create(&threadPID, NULL, ovListener, jsonData)) {
		log_info(fp, "\nError creating OpenVPN Listener Thread"); fflush(stdout);
		exit(1);
	}
	
	ovExec(jsonData);

	// TBD: For now use this to ensure that the listener runs and is 
	// waiting for pkts
	while(1) {
		sleep(2); 
		continue;
	}

	fclose(fp);
	fclose(fovStats);
	return 0;
}

