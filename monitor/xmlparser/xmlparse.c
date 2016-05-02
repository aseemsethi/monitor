#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <expat.h>
#include "xmlparse.h"
#include "../common/log.h"

FILE *flog_g = NULL;
//#define DEBUG 1

static int depth = 0;
static void XMLCALL charData (void *userData, const XML_Char *s, int len) {
	xmlData_t* xmlData = (xmlData_t*)userData;
	switch(xmlData->state) {
	case SERVERIP:
		xmlData->state = START;
		strncpy(xmlData->serverIP, s, len); xmlData->serverIP[len] = '\0';
		log_debug(flog_g, "Config: Server: %s, Len:%d", xmlData->serverIP, len);
		break;
	case PING:
		xmlData->state = START;
		xmlData->pingTimer = strtol(s, NULL, 0);
		log_debug(flog_g, "Config: PingTimer: %d", xmlData->pingTimer);
		break;
	case PING_DURATION:
		xmlData->state = START;
		xmlData->pingDuration = strtol(s, NULL, 0);
		log_debug(flog_g, "Config: PingDuration: %d", xmlData->pingDuration);
		break;
	case SSL_PORT:
		xmlData->state = START;
		xmlData->sslPort = strtol(s, NULL, 0);
		log_debug(flog_g, "Config: sslPort: %d", xmlData->sslPort);
		break;
	case SSL_PERSEC:
		xmlData->state = START;
		xmlData->sslPerSec = strtol(s, NULL, 0);
		log_debug(flog_g, "Config: sslPerSec: %d", xmlData->sslPerSec);
		break;
	}
	fflush(flog_g);
}

static void XMLCALL start (void *userData, const char *el, const char **attr) {
	xmlData_t *xmlData = userData;
	int i;
#ifdef DEBUG
	for (i=0;i<depth; i++)
		printf(" ");
	printf("%s", el);
#endif
	for (i=0;attr[i]; i+=2) {
		// printf("%s = %s", attr[i], attr[i+1]);
		if(strcmp(attr[i], "id") == 0) {
			xmlData->custID = strtol(attr[i+1], NULL, 0);
			printf("\n    Customer Config: ID:%d", xmlData->custID);
		}
	}
#ifdef DEBUG
	printf("\n"); 
	depth += 1;
#endif

	if(strcmp(el, "serverIP") == 0) xmlData->state = SERVERIP;
	else if(strcmp(el, "pingTimer") == 0) xmlData->state = PING;
	else if(strcmp(el, "pingDuration") == 0) xmlData->state = PING_DURATION;
	else if(strcmp(el, "sslPort") == 0) xmlData->state = SSL_PORT;
	else if(strcmp(el, "sslPerSec") == 0) xmlData->state = SSL_PERSEC;
	else xmlData->state = START;
}

static void XMLCALL end (void *data, const char *el) {
	depth--;
}

xmlData_t* parseConfig(char* id, FILE *flog)
{
	xmlData_t* xmlData;
	int len;
#define BUFFSIZE 8048
	char buff[BUFFSIZE];
	FILE *fp;
	char filePath[100];

	flog_g = flog;

	//xmlData is returnd to the caller, that needs to free it
	xmlData = malloc(sizeof(xmlData_t));
	if (xmlData == NULL) {
		log_debug(flog, "\n Malloc failure while alocation xmlData");
		return NULL;
	}

	XML_Parser p = XML_ParserCreate(NULL);
	if (!p) {
		log_error(flog, "Unable to create Parser");
		exit(-1);
	}
	log_debug(flog, "XML Parser created for CustID: %s, Size:%d",
				id, sizeof(xmlData_t));
	XML_SetElementHandler(p, start, end);
	XML_SetCharacterDataHandler(p, charData);
	XML_SetUserData(p, xmlData);

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], id);
	sprintf(&filePath[strlen("/var/monT/")+strlen(id)], "/config.xml");

	log_debug(flog, "Opening Customer Config File: %s", filePath);
	fp = fopen(filePath, "r");
	if (fp == NULL) {
		log_error(flog, "Config file not present..will wait for iNotify");
		fflush(flog);
		return NULL;
	}

	len = (int)fread(buff, sizeof(char), BUFFSIZE, fp); 
	log_debug(flog,"Read %d bytes from config file", len);
	if (XML_Parse(p, buff, strlen(buff), XML_TRUE) == XML_STATUS_ERROR) {
		log_error(flog,"Parser Error: %s", XML_ErrorString(XML_GetErrorCode(p)));
	}
	log_debug(flog,"**Customer Config: ID:%d, Server: %s, PingTimer: %d, PingDuration: %d, sslPort:%d, sslPerSec:%d", 
	xmlData->custID, xmlData->serverIP, xmlData->pingTimer, xmlData->pingDuration, xmlData->sslPort, xmlData->sslPerSec);
	fclose(fp);
	// TBD: This crashes the parser. Need to look into this.
	XML_ParserFree(p);
	return xmlData;
}

//#define PARSER_INDEPENDENT
#ifdef PARSER_INDEPENDENT
// compile with gcc -g xmlparse.c -lexpat
main() {
	FILE *fp;

	fp = fopen("tmpLog", "a");
	parseConfig("100", fp);
}
#endif
