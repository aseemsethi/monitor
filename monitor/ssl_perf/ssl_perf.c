#include "stdio.h"
#include "stdlib.h"
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#include <limits.h>
#include <netinet/in.h>
#include <arpa/inet.h> // for inet_ntoa
#include <linux/if_packet.h> //sll
#include <sys/ioctl.h> // SIOCGIFADDR
#include <netinet/ip_icmp.h>
#include <pthread.h>
#include "../xmlparser/xmlparse.h"
#include "../common/util.h"
#include "../common/log.h"
#include <net/if.h> // ifr
// SSL Stuff
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define INTERFACE "eth0"
#define SSL_PORT 4433
int getSelfIP();
FILE *fp;   
FILE *fsslStats;
int id = 0;  // stores the id of each sslPf struct allocated

typedef struct {
    int id;

    // Values that the program modifies
    int version_1;
    int version_2;
    int sessionID;

    char selfIP[INET_ADDRSTRLEN];
        
    // Unit under test
    struct sockaddr_in server_addr;
    struct sockaddr_ll sll;
    int sock;
} sslPerfStruct_t;
sslPerfStruct_t *sslPfQ[3000];

sslConnectToServer (sslPerfStruct_t *sslPf, xmlData_t* xmlData) {
  BIO              *certbio = NULL;
  BIO               *outbio = NULL;
  X509                *cert = NULL;
  X509_NAME       *certname = NULL;
  const SSL_METHOD *method;
  SSL_CTX *ctx;
  SSL *ssl;
  int server = 0;
  int ret, i;

  /* ---------------------------------------------------------- *
   * These function calls initialize openssl for correct work.  *
   * ---------------------------------------------------------- */
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  /* ---------------------------------------------------------- *
   * Create the Input/Output BIO's.                             *
   * ---------------------------------------------------------- */
  certbio = BIO_new(BIO_s_file());
  outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

  /* ---------------------------------------------------------- *
   * initialize SSL library and register algorithms             *
   * ---------------------------------------------------------- */
  if(SSL_library_init() < 0)
    BIO_printf(outbio, "Could not initialize the OpenSSL library !\n");

  /* ---------------------------------------------------------- *
   * Set SSLv2 client hello, also announce SSLv3 and TLSv1      *
   * ---------------------------------------------------------- */
  method = SSLv23_client_method();

  /* ---------------------------------------------------------- *
   * Try to create a new SSL context                            *
   * ---------------------------------------------------------- */
  if ( (ctx = SSL_CTX_new(method)) == NULL)
    BIO_printf(outbio, "Unable to create a new SSL context structure.\n");

  /* ---------------------------------------------------------- *
   * Disabling SSLv2 will leave v3 and TSLv1 for negotiation    *
   * ---------------------------------------------------------- */
  SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

  /* ---------------------------------------------------------- *
   * Create new SSL connection state object                     *
   * ---------------------------------------------------------- */
  ssl = SSL_new(ctx);

  /* ---------------------------------------------------------- *
   * Make the underlying TCP socket connection                  *
   * ---------------------------------------------------------- */
  server = sslPf->sock;

  /* ---------------------------------------------------------- *
   * Attach the SSL session to the socket descriptor            *
   * ---------------------------------------------------------- */
  SSL_set_fd(ssl, server);

  /* ---------------------------------------------------------- *
   * Try to SSL-connect here, returns 1 for success             *
   * ---------------------------------------------------------- */
  if ( SSL_connect(ssl) != 1 )
    BIO_printf(outbio, "Error: Could not build a SSL session to: %s.\n", sslPf->selfIP);
  else
    BIO_printf(outbio, "Successfully enabled SSL/TLS session to: %s.\n", sslPf->selfIP);

  /* ---------------------------------------------------------- *
   * Get the remote certificate into the X509 structure         *
   * ---------------------------------------------------------- */
  cert = SSL_get_peer_certificate(ssl);
  if (cert == NULL)
    BIO_printf(outbio, "Error: Could not get a certificate from: %s.\n", sslPf->selfIP);
  else
    BIO_printf(outbio, "Retrieved the sslPf.selfIP's certificate from: %s.\n", sslPf->selfIP);

  /* ---------------------------------------------------------- *
   * extract various certificate information                    *
   * -----------------------------------------------------------*/
  certname = X509_NAME_new();
  certname = X509_get_subject_name(cert);

  /* ---------------------------------------------------------- *
   * display the cert subject here                              *
   * -----------------------------------------------------------*/
  BIO_printf(outbio, "Displaying the certificate subject data:\n");
  X509_NAME_print_ex(outbio, certname, 0, 0);
  BIO_printf(outbio, "\n");

  /* ---------------------------------------------------------- *
   * Free the structures we don't need anymore                  *
   * -----------------------------------------------------------*/
  SSL_free(ssl);
  close(server);
  X509_free(cert);
  SSL_CTX_free(ctx);
  BIO_printf(outbio, "Finished SSL/TLS connection with server: %s.\n", sslPf->selfIP);
  return(0);
}

sslPerfCreateConn (sslPerfStruct_t *sslPf, xmlData_t* xmlData) {
    struct sockaddr_in;
    
    if((sslPf->sock=socket(AF_INET, SOCK_STREAM, 0)) == -1) {
            perror("socket:");
            log_error(fp, "SSL ERROR: create creation socket"); fflush(fp);
            exit(1);
    }
    sslPf->server_addr.sin_family = AF_INET;
    sslPf->server_addr.sin_port = htons(xmlData->sslPort);
    if(inet_aton(xmlData->serverIP, &sslPf->server_addr.sin_addr) == 0) {
            log_error(fp, "inet_aton() failed\n");
            log_error(fp, "SSL ERROR: create in inet_aton"); fflush(fp);
    }
    log_info(fp, "SSL: Connect to %s with sock: %d, sslId: %d", 
			xmlData->serverIP, sslPf->sock, sslPf->id);
    if(connect(sslPf->sock, (struct sockaddr *)&sslPf->server_addr,
                sizeof(struct sockaddr)) == -1) {
        log_error(fp, "SSL ERROR: create connecting to server"); fflush(fp);
        log_error(fsslStats, "SSL ERROR: create connecting to server");
        fflush(fsslStats);
        perror("Connect");
        exit(1);
    }
    log_info(fp, "TCP connection created to %s, sock:%d",
        xmlData->serverIP, sslPf->sock);
	fflush(fp);
}

sslPerfTestsExec (xmlData_t* xmlData) {
	sslPerfStruct_t *sslPf;
	int i;

	for (i = 0; i < xmlData->sslPerSec; i++) {
		sslPf = malloc(sizeof(sslPerfStruct_t));
		if (sslPf == NULL) {
			printf("\n Malloc failure at sslPerfStruct malloc"); exit(1);
		}
    	getOwnIP(sslPf->selfIP);
    	log_info(fp, "SSL: SelfIP: %s", sslPf->selfIP); fflush(fp);
		sslPf->id = id++;
		sslPfQ[id] = sslPf; // save the sslPf pointer for stats etc
		sslPerfCreateConn(sslPf, xmlData); // updates the sock in sslPf
		sslConnectToServer(sslPf, xmlData); // SSL Connect to Server using sslPf->sock
	}
}

int getOwnIP(char *ip) {
    int fd, status;
    struct ifreq ifr;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        log_error(fp, "ERROR: create scck for interface IP"); fflush(fp);
        return -1;
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, INTERFACE, IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) != 0) {
        perror("\nioctl failure");
        return -1;
    }
    close(fd);
    
    sprintf(ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    fflush(fp);
    
    return 0;
} 

void* sslPerfStart(void *args) {
    xmlData_t* xmlData = (xmlData_t*)args;
    char filePath[100];

    // ssl_logs
    sprintf(filePath, "/var/monT/");
    sprintf(&filePath[strlen("/var/monT/")], "%d", xmlData->custID);
    sprintf(&filePath[strlen(filePath)], "/ssl_perf_logs");
    fp = fopen(filePath, "a");

    // ssl_stats
    sprintf(filePath, "/var/monT/");
    sprintf(&filePath[strlen("/var/monT/")], "%d", xmlData->custID);
    sprintf(&filePath[strlen(filePath)], "/ssl_perf_stats");
    fsslStats = fopen(filePath, "a");

    fprintf(fp, "\nSSL Performance Tests started, Conn/Sec: %d", xmlData->sslPerSec);
	fflush(fp);
    sslPerfTestsExec(xmlData);

    while(1) {
        sleep(2);
        continue;
    }
    fclose(fp);
    fflush(stdout);
    return 0;
}
