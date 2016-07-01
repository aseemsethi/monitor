%{
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_packet.h> //sll
#include "../bgp/bgp.h"

typedef enum { BGP=1, OPENVPN=2, UPDATE=3, WITHDRAW=4, FNAME=5, EXIT=6,
			END=7, NEWLINE=8 } token_t;
typedef enum { ST_START=1, ST_PROTO=2, ST_END=3 } state_t;
typedef enum { BGP_PROTO=1, OPENVPN_PROTO=2 } proto_t;
token_t token;
char *token_txt;
int protocol=0, state=ST_START;
extern bgp_t bgp;
%}
%%
^bgp		return BGP;
^openvpn	return OPENVPN;
^update[ ][A-Za-z0-9]+ { token_txt = strdup(yytext); return UPDATE; }
^withdraw[ ][A-Za-z0-9]+ { token_txt = strdup(yytext); return WITHDRAW; }
^exit		return END;
^[A-Za-z0-9]+	{ token_txt = strdup(yytext); return FNAME; }
^\n			return NEWLINE;
%%
sendUpdateCli(char *fileName) {
	FILE *fu;
	char filePath[100];

	sprintf(filePath, fileName);
	fu = fopen(filePath, "r");
	if (fu == NULL) {
		printf("Update file %s not present..", filePath); fflush(stdout);
		return -1;
	}
	sendUpdateFile(&bgp, fu);
}
sendWithdrawCli(char *fileName) {
	FILE *fw;
	char filePath[100];

	sprintf(filePath, fileName);
	fw = fopen(filePath, "r");
	if (fw == NULL) {
		printf("Withdraw file %s not present..", filePath); fflush(stdout);
		return -1;
	}
	sendUpdateWithdrawFile(&bgp, fw);
}

int mainShell(int argc, char *argv[]) {
	while( (token=yylex()) ) {
		switch(token) {
		case BGP:
			if (state == ST_START) {
				protocol = BGP_PROTO;
				state = ST_PROTO;
			}
			break;
		case OPENVPN:
			if (state == ST_START) {
				protocol = OPENVPN_PROTO;
				state = ST_PROTO;
			}
			break;
		case UPDATE:
			if (state == ST_PROTO) {
				printf("Reading file (UPD):%s\n", &token_txt[7]);
				sendUpdateCli(&token_txt[7]);
			}
			break;
		case WITHDRAW:
			if (state == ST_PROTO) {
				printf("Reading file (WDR):%s\n", &token_txt[9]);
				sendWithdrawCli(&token_txt[9]);
			}
			break;
		case END:
			printf("\nProto Exit"); state = ST_START; protocol=0; break;
		case NEWLINE:
			break;
		default:
			printf("Unknown command");
		}
		if(protocol==BGP_PROTO) printf("bgp>"); else
		if(protocol==OPENVPN_PROTO) printf("openvpn>");
		else printf("proto>"); fflush(stdout);
	}
	printf("\n Exiting parser"); fflush(stdout);
}

int yywrap() {
	printf("\n yywrap called");
	return 1;
}
