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
	int version;
    char routerID[30];
	int withdrawnLen; 
	int withdrawnPrefix[20]; char withdrawnRoute[20][20];
	int pathAttrLen;
	int pathFlag[20]; int pathType[20]; int pathLen[20]; int pathValue[20];
	char pathValueNextHop[20][20];
	int nlriLen[20]; char nlriPrefix[20][20];
	int nIndex;
	int pathIndex;
	int wIndex;
} jsonData_t;

