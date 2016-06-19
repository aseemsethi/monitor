/* packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte */
#define P_KEY_ID_MASK              0x07
#define P_OPCODE_SHIFT             3
#define P_KEYID_MASK               0xF8 

/* packet opcodes -- the V1 is intended to allow protocol changes in the future */
#define P_CONTROL_HARD_RESET_CLIENT_V1 1     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V1 2     /* initial key from server, forget previous state */
#define P_CONTROL_SOFT_RESET_V1        3     /* new key, graceful transition from old to new key */
#define P_CONTROL_V1                   4     /* control channel packet (usually TLS ciphertext) */
#define P_ACK_V1                       5     /* acknowledgement for packets received */
#define P_DATA_V1                      6     /* data channel packet */
#define P_DATA_V2                      9     /* data channel packet with peer-id */

/* indicates key_method >= 2 */
#define P_CONTROL_HARD_RESET_CLIENT_V2 7     /* initial key from client, forget previous state */
#define P_CONTROL_HARD_RESET_SERVER_V2 8     /* initial key from server, forget previous state */


typedef struct {
    FILE *fp;
    FILE *fovStats;
    char selfIP[INET_ADDRSTRLEN];
	jsonData_t* jsonData;

    // Unit under test
    struct sockaddr_in server_addr;
    int sock;
    int seqNo;
    int replayNo;

	// Recvd from the peer
    int toAck;
	uchar toSessionID[8];
} ovStruct_t;

