/*
 * The main() program is execvp from the RPC server in server.c
 */
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "pthread.h"
#include "errno.h"
#include <sys/stat.h>
#include "../xmlparser/xmlparse.h"
#include "log.h"

FILE *fmont;
pthread_t sslPID;
extern pingPid, ping_seq, ping_lost;


xmlData_t* parseConfig(char*, FILE *flog);
void* pingStart(void *args);
void* sslStart(void *args);

startSslThread(xmlData_t* xmlData) {
	struct stat st;
	char filePath[100];
	
	// Create SSL thread
	log_debug(fmont, "CUST: Create SSL thread.."); fflush(fmont);
	if (pthread_create(&sslPID, NULL, sslStart, (void*)xmlData)) {
		log_error(fmont, "Error creating SSL Thread"); fflush(fmont);
		exit(1);
	}
	fflush(fmont);
}

/*
    sprintf(filePath, "/proc/");
	sprintf(&filePath[strlen("/proc/")], "%d", pingPid);
	if (stat(filePath, &st) == -1 && errno == ENOENT) {
		log_debug(fmont, "\nCUST: Ping Process %d does not exist", pingPid);
	} else {
		log_debug(fmont, "\nCUST: Ping process already running, PID:%d", pingPid);
		fflush(fmont);
		return;
	}
*/

/*
 * This is called with "prog", "name", "id". The "name" is the monitor 
 * process that needs to be started. 
 * Open the log file and read the config file
 * Start the Monitor thread that has been requested.
 *
 * The client RPC command line looks like
 *       ./mont_client localhost ./mont_cust ping 100
 */
main(int argc, char *argv[]) {
	xmlData_t* xmlData;
	char filePath[100];

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], argv[1]);
	sprintf(&filePath[strlen(filePath)], "/cust_logs");
	printf("\n %s", filePath);
	fmont = fopen(filePath, "a");
	if (fmont == NULL) {
		printf("\nDir missing /var/monT/%s: Exiting mont_cust process",
				argv[1]);
		fflush(stdout); return;
	}

	log_debug(fmont, "LOG Monitor: %d params:%s:%s", argc, argv[1], argv[2]);

	// Read in the config for customer id: argv[1]
	xmlData = parseConfig(argv[1], fmont);
	if (xmlData == NULL) {
		log_error(fmont, "No config in /var/monT/%s: Exiting mont_cust process",
				argv[1]);
		fflush(fmont); return;
	}
	if(strcmp(argv[2], "ssl") == 0) {
		log_info(fmont, "RPC has requested SSL Monitoring");
		startSslThread(xmlData);
	} else {
		log_info(fmont, "RPC has NOT requested SSL Monitoring");
	}
	fflush(fmont);

	// TBD : Start CLI parser thread here, vs sleeping
	while(1) {
		sleep(2);
		fflush(stdout);
	}
}
