#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h> // for inet_ntoa
#include <linux/if_packet.h> //sll
#include <sys/ioctl.h>
#include <netinet/ip_icmp.h>
#include "../xmlparser/xmlparse.h"
#include <sys/signal.h>
#include "ssl.h"
#include "../common/log.h"
#include "util.h"

#define PASS 1
#define FAIL 0
#define SSL_NUM_TESTS 6


FILE *fp;
void* recvFunction(void *arg);

typedef struct {
	char cveId[30];
	int (*init_params)(sslStruct *ssl, param_t *args);
	int (*send)(sslStruct *ssl, param_t *args);
	int (*verify)(sslStruct *ssl, param_t *args);
	int (*update_stats)(sslStruct *ssl, param_t *args, char* details);
	int (*send_again)(sslStruct *ssl, param_t *args);
	int (*verify_again)(sslStruct *ssl, param_t *args);
	char details[240];
} sslTests_t;


typedef struct {
	char cveId[20];
	int  result;
} sslTestsResults_t;

sslTestsResults_t sslTestsResults[SSL_NUM_TESTS];


encrypt (sslStruct *sslP, char *buff, char *encryptedBuf, int len) {
    int padding = RSA_PKCS1_PADDING;
    int result;

    // The encrypted bufer must be of size RSA_size(rsa_key)
    printf("\nRSA Size = %d", RSA_size(sslP->paramP->rsa_key));
    result = RSA_public_encrypt(len, buff, encryptedBuf,
                sslP->paramP->rsa_key, padding);
    return result;
}

sendServerKeyExchange (sslStruct *sslP, param_t *args) 	{ 
	// server_key_exchange = 12, client_key_exchange = 16
	args->hello_value = server_key_exchange; 
	sendClientKeyExchange(sslP, args);
}

sendClientKeyExchange (sslStruct *sslP, param_t *args) 	{ 
	uchar buff[1024];
	uchar plainText[256];
	uchar encryptedBuf[256];
	uchar *p = &buff[0];
	ushort length = 0;
	struct timeval tv;
	time_t curtime;
	int status, result;
	int i;

	// First parse ServerHelloDone
	status = recvServerHelloDone(sslP);
	// Record Hdr (Type, Version, Length)
	p[0] = handshake; //0x16
	// TLS ver 1.2 uses version value 3.3
	// SSL v3 is version 0300
	p[1] = SSL_VERSION_1;
	p[2] = SSL_VERSION_2;
	PUT_BE16(&p[3], 0); // **** fill in this later at this point
	// current length, used by sendData, and also in pkt
	length = RECORD_HDR_LEN;

	// Note that we have done 5 bytes by now, which should be substracted
	// from the pkt length for the RecordProtocol.

	p[5] = args->hello_value; // client_key_exchange = 16
	p[6] = 0;  // 3rd MSByte of the Length, usualy 0
	// length of Handshake pkt following length field = 1 byte
	PUT_BE16(&p[7], 0); // **** fill in this later at this point
	length = length + 4;

	// pre-master secret encrypted with Server's public key
	// Total Len = 48 bytes (2 byte version, 46 byte key)
	// Fil in the 2 Byte Version first
	plainText[0] = SSL_VERSION_1; 
	plainText[1] = SSL_VERSION_2;
	// Now fill in the secret key of 46 Bytes
	// Also save in sslP struct to create master secret
	strcpy(&plainText[2], "aseem sethi's private key01234567890123456789");
	memcpy(&(sslP->paramP->preMasterSecret[0]), &plainText[0], 48);
	result = encrypt(sslP, &plainText[0], &encryptedBuf[0], 48);
	printf("\n Encrypted Len = %d", result);
	memcpy(&p[9], &encryptedBuf[0], result);
	length = length + result;

	// Finally fill in the lengths of Record and Handshake headers
	PUT_BE16(&p[3], length-RECORD_HDR_LEN);
	PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
	// Save Client Msgs for making the Finished Msg
	memcpy(&(sslP->paramP->clientHandshakeMsgs[sslP->paramP->clientHandshakeMsgsIndex]), 
		&(p[5]), length-RECORD_HDR_LEN);
	sslP->paramP->clientHandshakeMsgsIndex = 
		sslP->paramP->clientHandshakeMsgsIndex + length-RECORD_HDR_LEN;
	printf("\n-> Send Client Key Exchange");
	sendData(sslP, buff, length);
}

// 2nd Phase of Testing - post ClientHello/ServerHello
int verifyAgainNull (sslStruct *sslP, param_t *args) 	{ 
	return 0;
}
int sendAgainNull (sslStruct *sslP, param_t *args) 	{ 
	return 0;
}

int initSessionId (sslStruct *sslP, param_t *args) 	{ 
	initParams(sslP, args);
	args->sessionID = 100;
}

int initServerHello (sslStruct *sslP, param_t *args) 	{ 
	initParams(sslP, args);
	args->hello_value = server_hello; // 0x1
}

int initCipherCheck (sslStruct *sslP, param_t *args) 	{ 
	initParams(sslP, args);
	// cypher suites
	args->cipher[0] = 0; 
	args->cipher[1] = 2; // Length of cypher suite
	args->cipher[2] = 0x99;
	args->cipher[3] = 0x99;
	args->cipherLen = 4;
}

int initParamsVerCheck (sslStruct *sslP, param_t *args) 	{ 
	initParams(sslP, args);
	args->version_1 = 4;
	args->version_2 = 4;
}

int initParams (sslStruct *sslP, param_t *args) 	{ 
	struct timeval tv;
	time_t curtime;
	int i;

	sslP->paramP->handshakeResp = 0;
    sslP->paramP->handshakeMsgsIndex = 0; // Msgs recvd from Server for MD5/SHA1
    sslP->paramP->clientHandshakeMsgsIndex = 0; // Msgs saved for MD5/SHA1
    //memset(sslP->paramP->buff, 0, 1024);

	gettimeofday(&tv, NULL);
	curtime=tv.tv_sec;
	char buf[32];
	args->version_1 = SSL_VERSION_1;
	args->version_2 = SSL_VERSION_2;
	args->sessionID = 0;
	args->hello_value = client_hello; // 0x1
	
	// Random Structure
	PUT_BE32(&buf[0], curtime);
	for (i=4; i<=31; i++)
			buf[i] = 0;
	//Save the random value into sslP. Used later in the Finished msg
	memcpy(&(args->random[0]), &buf[0], 32);
	
	// cypher suites
	args->cipher[0] = 0; // Length of cypher suite
	args->cipher[1] = 2; // Length of cypher suite
	args->cipher[2] = TLS_RSA_WITH_RC4_128_SHA_1;
	args->cipher[3] = TLS_RSA_WITH_RC4_128_SHA_2;
	args->cipherLen = 4;
}

int sendHello (sslStruct *sslP, param_t *args) 	{ 
	uchar buff[1024];
	uchar *p = &buff[0];
	ushort length = 0;
	int i;

	log_debug(fp, "SSL: SendHello"); fflush(stdout);

	// Record Hdr (Type, Version, Length)
	p[0] = handshake; //0x16
	// SSL 3.0 is 0x0300, TLS ver 1.0 = 3.1, TLS 1.2 is 3.3, 
	// SSL_VERSION used here is 3.1
	p[1] = args->version_1; //SSL_VERSION_1;
	p[2] = args->version_2; //SSL_VERSION_2;
	PUT_BE16(&p[3], 0); // **** fill in this later at this point
	// current length, used by sendData, and also in pkt
	length = RECORD_HDR_LEN;

	// Note that we have done 5 bytes by now, which should be substracted
	// from the pkt length for the RecordProtocol.

	p[5] = args->hello_value; // client_hello = 0x1
	p[6] = 0;  // 3rd MSByte of the Length, usualy 0
	// length of Handshake pkt following length field = 1 byte
	PUT_BE16(&p[7], 0); // **** fill in this later at this point
	length = length + 4;

	p[9] =  args->version_1; // SSL_VERSION_1;
	p[10] =  args->version_2; // SSL_VERSION_2;
	length = length + 2;

	memcpy(&p[11], &(args->random[0]), 32); // copy from args into buffer
	length += 32;
	p[43] = args->sessionID; // sessionID
	length++;

	memcpy(&p[44], &(args->cipher[0]), args->cipherLen); 
	length += args->cipherLen; // currently set to 4

	p[48] = 1; //length of compression vector
	p[49] = 0; //compression algorithm
	length += 2;

	// Finally fill in the lengths of Record and Handshake headers
	PUT_BE16(&p[3], length-RECORD_HDR_LEN);
	PUT_BE16(&p[7], length-RECORD_HDR_LEN-4);
	// Save Client Msgs for making the Finished Msg
	memcpy(&(args->clientHandshakeMsgs[args->clientHandshakeMsgsIndex]), 
	&(p[5]), length-RECORD_HDR_LEN);
	args->clientHandshakeMsgsIndex = 
		args->clientHandshakeMsgsIndex + length-RECORD_HDR_LEN;
	log_debug(fp, "-> Send Client Hello, Len:%d", length); fflush(stdout);
	sendData(sslP, buff, length);
}

int verifyFailed (sslStruct *sslP, param_t *args) { 
	if (sslP->paramP->handshakeResp & (0x01 <<server_hello)) {
		log_debug(fp, "Server Hello Recvd."); fflush(fp);
		sslTestsResults[args->testId].result = FAIL;
	} else {
		log_debug(fp, "Server Hello NOT Recvd. %x", sslP->paramP->handshakeResp); fflush(fp);
		sslTestsResults[args->testId].result = PASS;
	}
}
int verifyPassed (sslStruct *sslP, param_t *args) { 
	if (sslP->paramP->handshakeResp & (0x01 <<server_hello)) {
		log_debug(fp, "Server Hello Recvd."); fflush(fp);
		sslTestsResults[args->testId].result = PASS;
	} else {
		log_debug(fp, "Server Hello NOT Recvd. %x", sslP->paramP->handshakeResp); fflush(fp);
		sslTestsResults[args->testId].result = FAIL;
	}
}

/*
 * TBD: Generally, we should check for a receipt of ALERT, that indicates 
 * an SSL Protocol error and closure of SSL connection.
 * This function updates STATS file only.
 */
int updateStats (sslStruct *sslP, param_t *args, char* details) { 
	if (sslTestsResults[args->testId].result == PASS) {
		log_info(sslP->fsslStats, "Test ID: %s, Pass", 
			sslTestsResults[args->testId].cveId);
	} else {
		log_info(sslP->fsslStats, "Test ID: %s, Fail: Details:", 
			sslTestsResults[args->testId].cveId);
	}
	log_info(sslP->fsslStats, "Test Details: %s", details);
	fflush(sslP->fsslStats);
	return sslTestsResults[args->testId].result;
}

sslTestsDump() {
	char result[20];
	int i;

	for (i=0;i<SSL_NUM_TESTS;i++) {
		log_debug(fp, "--------------Test Results--------------");
		if (sslTestsResults[i].result == 1) strcpy(result, "pass"); 
		else strcpy(result, "fail");
		log_debug(fp, "Test ID: %s, Pass/Fail:%s", 
					sslTestsResults[i].cveId, result );
	}
	log_debug(fp, "----------------------------------------");
	fflush(fp);
}

static void signal_handler(int sig) {
	int i;
	if (sig == SIGUSR1) {
		printf("\n SIGUSR1 !"); fflush(stdout);
		sslTestsDump();
	}
}

#include "sslTestCases"

signalRecvThread(sslStruct *sslP) {
	struct timespec tim1;
	tim1.tv_sec=0;
	tim1.tv_nsec=800000000L;
	if (nanosleep(&tim1, NULL) < 0) {
		log_error(sslP->fp, "SSL: Error: nanosleep call failed!");
		return -1;
	} 
	return 0;
}

sslTestsExec(sslStruct *sslP, xmlData_t* xmlData) {
	int i, status;
	struct sigaction sigact;
	struct timespec tim1;
	pthread_t recvThread;
	char result[20];

    initConnectionToServer(sslP, xmlData);
    status = pthread_create(&recvThread, NULL, &recvFunction, (void*)sslP);
    if (status != 0) { perror("Start Thread Error:"); return -1; }

	fp = sslP->fp; // ssl_logs
	// Initialize signals
    sigact.sa_handler = signal_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGUSR1, &sigact, (struct sigaction*) NULL);

	for (i=0;i<SSL_NUM_TESTS;i++) {
		log_debug(sslP->fp, "Exec Test:%d", i); fflush(sslP->fp);
		sslP->paramP->testId = i;
		strncpy(sslTestsResults[i].cveId, sslTests[i].cveId, 
				strlen(sslTests[i].cveId));
		// The following call sets relevant sslP->paramP params
		sslTests[i].init_params(sslP, sslP->paramP);
		pthread_mutex_lock(&sslP->lock);
		sslTests[i].send(sslP, sslP->paramP);
		pthread_mutex_unlock(&sslP->lock);

		// Wait for recvThread to signal that we can proceed with 
		// the verification step below
		// TBD: For now, Sleep for 0.8 Sec, giving a chance to recvThread
		tim1.tv_sec=0;
		tim1.tv_nsec=800000000L;
		if (nanosleep(&tim1, NULL) < 0) {
			log_error(sslP->fp, "SSL: Error: nanosleep call failed!");
			return -1;
		} 

		sslTests[i].verify(sslP, sslP->paramP);
/* 
 * Note that in the results(), if we find there is a failure, the 
 * socket might be closed. So, we need to ensure that there is a 
 * new socket created, before running further tests.
 * In fact, let's create a new conn, for every test
 * TBD: kill the recvThread too at this point, since we spawn it again
 */
		if (sslTests[i].update_stats(sslP, sslP->paramP, sslTests[i].details) 
					== FAIL) {
			log_error(sslP->fp, "\nSSL: TestsExec: Failed Test %d", i);
		} else {
		// 1st State Passed...
		// 2nd State, after ClientHello/ServerHello
		sslTests[i].send_again(sslP, sslP->paramP);
		signalRecvThread(sslP);
		sslTests[i].verify_again(sslP, sslP->paramP);
		sslTests[i].update_stats(sslP, sslP->paramP, sslTests[i].details); 
		}

// Final Cleanup
		close(sslP->sock);
		status = pthread_cancel(recvThread);
		if (status != 0) {
			log_error(sslP->fp, "\nSSL: Failed to cancel thread");
			fflush(sslP->fp);
			perror("SSL: Failed to cancel thread");
			exit(1);
		}
		sslP->paramP->handshakeResp = 0;
    	initConnectionToServer(sslP, xmlData);
 		status = pthread_create(&recvThread, NULL, &recvFunction, 
					(void*)sslP);
    	if (status != 0) { perror("Start Thread Error:"); return -1; }
	} // for all tests

	// Put in a summary report into stats
	for (i=0;i<SSL_NUM_TESTS;i++) {
		log_info(sslP->fsslStats, "---------Test Results Summary------------");
		if (sslTestsResults[i].result == 1) strcpy(result, "pass"); 
		else strcpy(result, "fail");
		log_info(sslP->fsslStats, "Test ID: %s, Pass/Fail:%s", 
					sslTestsResults[i].cveId, result );
	}
	log_info(sslP->fsslStats, "---------------------------------------------");
	fflush(sslP->fsslStats);
}
