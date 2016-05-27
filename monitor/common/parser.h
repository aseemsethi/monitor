typedef unsigned short u16;
typedef unsigned short ushort;
typedef unsigned long u32;
typedef unsigned char u8;
typedef unsigned char uchar;

typedef struct {
    int state;
    int custID;
    char serverIP[30]; // Same for Ping and SSL server

	// SSL Params
	int sslPort;
    int sslPerSec;
	
	// SSL Perf Params
    int totalConn;
	int helloPerSec;
    int totalHello;

	// HTTP Params
    char url[255];
    int httpSessions;
    int httpParallel;
    int pktSize;
    int httpVerbose;

	// BGP Params
    char routerID[30];
	int withdrawnLen; 
	int withdrawnPrefix[4]; char withdrawnRoute[4][20];
	int pathAttrLen;
	int pathFlag[4]; int pathType[4]; int pathLen[4]; int pathValue[4];
	char pathValueNextHop[4][20];
	int nlriLen; char nlriPrefix[20];
	int nlriIndex;
	int pathIndex;
	int wIndex;
} jsonData_t;

