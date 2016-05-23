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
} jsonData_t;

