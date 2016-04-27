#include <linux/if_packet.h> //sll
#include <sys/ioctl.h>
#include <net/if.h>

#define INTERFACE "eth0"
#define SSL_PORT 4433
#define SSL_VERSION_1 3
#define SSL_VERSION_2 1
#define RECORD_HDR_LEN 5
#define SSL_INNER_HDR_LEN 4

// Events
#define HELLO_REQ               0
#define CLIENT_HELLO    1
#define SERVER_HELLO    2
#define CERTIFICATE             3
#define SERVER_KEY_EXCHANGE     4
#define CERTIFICATE_REQ         5
#define SERVER_HELLO_DONE       6
#define CERTIFICATE_VERIFY      7
#define CLIENT_KEY_EXCHANGE     8
#define FINISHED                        9
#define CHANGE_CIPHER_SPEC      10
// States
#define SSL_INIT 0
#define SSL_HELLO_DONE_RECVD 1
#define SSL_CHANGE_CIPHER_SPEC_RECVD 2
#define SSL_FINISHED_RECVD 3

typedef struct {
    // Set before every test
    int testId;

    // Values that the program modifies
    int version_1;
    int version_2;
	int sessionID;
	char cipher[3];
	int cipherLen;
	int hello_value;

    int state;
    uchar *buff;
    int buffLen;
    char srcIP[20];
    ushort srcPort;
    //char sessionIDLen;
    //char sessionID[40];
    int versionResp[2];
    int handshakeResp;
    // RSA *rsa_key;
    // Stuff needed to create MasterSecret
    uchar handshakeMsgs[6000];
    int handshakeMsgsIndex;
    uchar clientHandshakeMsgs[6000];
    int clientHandshakeMsgsIndex;
    uchar random[32];
    uchar serverRandom[32];
    uchar preMasterSecret[48];
    uchar masterSecret[48];
} param_t;

typedef struct {
	FILE *fp;
	FILE *fsslStats;
    char selfIP[INET_ADDRSTRLEN];

    // Unit under test
    struct sockaddr_in server_addr;
    struct sockaddr_ll sll;
    int sock;
    param_t *paramP;
	pthread_mutex_t lock;
} sslStruct;

/**********
 Record Protocol Header
 **********/
typedef enum {
        change_cipher_spec = 20, alert = 21, handshake = 22,
        application_data = 23
} ContentType;

typedef struct {
          uchar major;
          uchar minor;
} ProtocolVersion;

typedef struct {
        ContentType type;
        ProtocolVersion version;
        u16 length;
} RecordHdrPlainTxt;
/**********
 Record Protocol Header
 **********/
typedef enum {
          hello_request=0, client_hello=1, server_hello=2,
          certificate=11, server_key_exchange =12,
          certificate_request=13, server_hello_done=14,
          certificate_verify=15, client_key_exchange=16,
          finished=20
} HandshakeType;


// TBD - change the following as _1 and _2 
#define TLS_RSA_WITH_NULL_MD5 "0x00,0x01"
#define TLS_RSA_WITH_NULL_SHA "0x00,0x02"
#define TLS_RSA_WITH_NULL_SHA256 "0x00,0x3B"
#define TLS_RSA_WITH_RC4_128_MD5 "0x00,0x04"
#define TLS_RSA_WITH_RC4_128_SHA_1 0x00
#define TLS_RSA_WITH_RC4_128_SHA_2 0x05
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA "0x00,0x0A"
#define TLS_RSA_WITH_AES_128_CBC_SHA  "0x00,0x2F"
#define TLS_RSA_WITH_AES_256_CBC_SHA  "0x00,0x35"
#define TLS_RSA_WITH_AES_128_CBC_SHA256 "0x00,0x3C"
#define TLS_RSA_WITH_AES_256_CBC_SHA256 "0x00,0x3D"
