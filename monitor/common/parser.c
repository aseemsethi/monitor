#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "log.h"
#include "../../jsmn/jsmn.h"
#include "parser.h"

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
            strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

jsonData_t* parse (char* id, FILE *flog) {
	jsmn_parser p;
	jsmntok_t *tok;
	size_t tokcount = 256;
	int i, r, len, tlen, ret;
#define BUFFSIZE 8048
	char buff[BUFFSIZE];
	FILE *fp;
	char filePath[100];
	jsonData_t* jsonData;
	jsmntok_t *t;

	// jsonData is returnd to the caller, that needs to free it
	jsonData = malloc(sizeof(jsonData_t));
	if (jsonData == NULL) {
		log_debug(flog, "\n Malloc failure while alocation jsonData");
		return NULL;
	}

	sprintf(filePath, "/var/monT/");
	sprintf(&filePath[strlen("/var/monT/")], id);
	sprintf(&filePath[strlen("/var/monT/")+strlen(id)], "/config.json");
	log_debug(flog, "Opening Customer Config File: %s", filePath);
	fp = fopen(filePath, "r");
	if (fp == NULL) {
		log_error(flog, "Config file not present..");
		fflush(flog);
		return NULL;
	}

	len = (int)fread(buff, sizeof(char), BUFFSIZE, fp); 
	log_debug(flog,"Read %d bytes from config file", len);

	jsmn_init(&p);
	tok = malloc(sizeof(*tok) * tokcount);
	if (tok == NULL) {
		printf("\n malloc error in parser");
		exit(1);
	}
    r = jsmn_parse(&p, buff, len, tok, tokcount);
    if (r < 0) {
            if (r == JSMN_ERROR_NOMEM) {
				printf("\n Parse: Allocate more mem to tok"); return NULL; }
			if (ret == JSMN_ERROR_INVAL) {
				printf("\n Parse: invalid JSON string"); return NULL; }
			if (ret == JSMN_ERROR_PART) {
				printf("\n Parse: truncated JSON string"); return NULL; }
	} else {
		char s[20];
		printf("\n jsmn_parse returned %d", r);
		for (i = 0; i < r; i++) {
			strncpy(s, buff + tok[i+1].start,  tok[i+1].end-tok[i+1].start); 
			s[tok[i+1].end-tok[i+1].start] = '\0';
			if (jsoneq(buff, &tok[i], "custID") == 0) {
				printf("\n custID: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start);
				jsonData->custID = strtol(s, NULL,0);
				i++;
			} else if (jsoneq(buff, &tok[i], "serverIP") == 0) {
				printf("\n serverIP: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start); 
				strncpy(jsonData->serverIP, buff + tok[i+1].start,  tok[i+1].end-tok[i+1].start); jsonData->serverIP[tok[i+1].end-tok[i+1].start] = '\0';
				i++;
			} else if (jsoneq(buff, &tok[i], "sslPort") == 0) {
				printf("\n sslPort: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start);
				jsonData->sslPort = strtol(s, NULL,0);
				i++;
			} else if (jsoneq(buff, &tok[i], "sslPerSec") == 0) {
				printf("\n sslPerSec: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start);
				jsonData->sslPerSec = strtol(s, NULL,0);
				i++;
			} else if (jsoneq(buff, &tok[i], "totalConn") == 0) {
				printf("\n totalConn: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start);
				jsonData->totalConn = strtol(s, NULL,0);
				i++;
			} else if (jsoneq(buff, &tok[i], "helloPerSec") == 0) {
				printf("\n helloPerSec: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start);
				jsonData->helloPerSec = strtol(s, NULL,0);
				i++;
			} else if (jsoneq(buff, &tok[i], "totalHello") == 0) {
				printf("\n totalHello: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start);
				jsonData->totalHello = strtol(s, NULL,0);
				i++;
			} else if (jsoneq(buff, &tok[i], "httpVerbose") == 0) {
				printf("\n httpVerbose: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start);
				jsonData->httpVerbose = strtol(s, NULL,0);
				i++;
			} else if (jsoneq(buff, &tok[i], "httpParallel") == 0) {
				printf("\n httpParallel: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start);
				jsonData->httpParallel = strtol(s, NULL,0);
				i++;
			} else if (jsoneq(buff, &tok[i], "httpSerial") == 0) {
				printf("\n httpSerial: %.*s", tok[i+1].end-tok[i+1].start,
					buff + tok[i+1].start); 
				jsonData->httpSerial = strtol(s, NULL,0);
				i++;
			}
		}
	}
	log_debug(flog,"**Customer Config: ID:%d, Server: %s, sslPort: %d, sslPerSec: %d, totalConn: %d, helloPerSec:%d, totalHello:%d, httpParallel:%d, httpSerial:%d, httpVerbose:%d", 
	jsonData->custID, 
	jsonData->serverIP, jsonData->sslPort, 
	jsonData->sslPerSec, jsonData->totalConn, 
	jsonData->helloPerSec, jsonData->totalHello,
	jsonData->httpParallel, jsonData->httpSerial, jsonData->httpVerbose);
	fclose(fp);
	return jsonData;
}

/*
main() {
	FILE *fp;
	jsonData_t* jsonData;

	fp = fopen("./tmp", "a");
	jsonData = parse("100", fp);
}
*/
