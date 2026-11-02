/*
 * tls_mt_server.c -- serveur TLS 1.3 MULTI-CONNEXIONS (un thread par connexion) pour la campagne de charge
 * concurrente (campagne v3).
 *
 * POURQUOI : `openssl s_server` (utilise dans la campagne v2) traite les connexions UNE PAR UNE : apres accept(),
 * il execute tout l'echange (handshake, requete, reponse, fermeture) avant d'accepter la suivante
 * (apps/lib/s_socket.c : do_server -> (*cb)(sock, ...)). Pendant les attentes reseau (RTT), il ne fait rien d'autre.
 * Ce n'est pas un serveur concurrent : il ne peut pas servir de base a une etude de charge. Le serveur QUIC
 * (MsQuic) est, lui, evenementiel et multi-connexions. Ce programme donne a TLS la meme propriete.
 *
 * FIDELITE AU SERVEUR DE LA CAMPAGNE v2 :
 *  - meme libssl (donc memes enregistrements, meme tampon d'ecriture BIO de 4096 octets, meme vol de 10 215 o
 *    pour ML-DSA-65 + X448/ML-KEM-768) ; TCP_NODELAY comme s_server (BIO_set_tcp_ndelay) ;
 *  - meme reponse applicative que `s_server -WWW` : en-tete "HTTP/1.0 200 ok" puis 100 octets de corps (fichier
 *    payload), en deux ecritures ; pas de ticket de session par defaut (-num_tickets 0) ;
 *  - groupes de cles : -groups (SSL_CTX_set1_groups_list), sinon la configuration openssl.cnf (DEFAULT_GROUPS).
 *
 * LIMITES : authentification simple uniquement (pas de -verify) ; pas de reprise sauf -tickets N > 0 ;
 * un thread par connexion (pas de pool) : suffisant jusqu'a quelques centaines de connexions simultanees.
 *
 * USAGE : tls_mt_server -port 4433 -cert server.crt -key server.key [-cert_chain ICA.crt] [-groups G]
 *                       [-payload payload.bin] [-tickets N] [-cert_comp none|zlib|brotli|zstd]
 * Compilation : gcc -O2 -pthread tls_mt_server.c -o tls_mt_server -I$PREFIX/include -L$PREFIX/lib64 -lssl -lcrypto
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#define PAYLOAD_MAX 65536
#define HDR "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n"

static SSL_CTX *g_ctx;
static unsigned char g_payload[PAYLOAD_MAX];
static size_t g_payload_len = 100;

typedef struct { int fd; } conn_arg;

static void *serve(void *p)
{
    conn_arg *a = (conn_arg *)p;
    int fd = a->fd;
    free(a);
    int one = 1;
    char req[1024];
    size_t n = 0;
    SSL *ssl = SSL_new(g_ctx);
    if (ssl == NULL) { close(fd); return NULL; }
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) <= 0)
        goto done;
    /* Lire la requete jusqu'a la ligne vide (GET ... HTTP/1.0\r\n\r\n). */
    while (n < sizeof(req) - 1) {
        int r = SSL_read(ssl, req + n, (int)(sizeof(req) - 1 - n));
        if (r <= 0)
            goto done;
        n += (size_t)r;
        req[n] = '\0';
        if (strstr(req, "\r\n\r\n") != NULL || strstr(req, "\n\n") != NULL)
            break;
    }
    /* Reponse comme `s_server -WWW` : en-tete puis corps (deux ecritures). */
    if (SSL_write(ssl, HDR, (int)(sizeof(HDR) - 1)) <= 0)
        goto done;
    (void)SSL_write(ssl, g_payload, (int)g_payload_len);
    SSL_shutdown(ssl);
done:
    SSL_free(ssl);
    close(fd);
    return NULL;
}

int main(int argc, char **argv)
{
    int port = 4433, i, ntickets = 0;
    const char *cert = NULL, *key = NULL, *chain = NULL, *groups = NULL, *payload = NULL, *cert_comp = NULL;

    for (i = 1; i < argc; i++) {
        const char *k = argv[i];
        while (*k == '-') k++;
        if (i + 1 >= argc) { fprintf(stderr, "option %s sans valeur\n", argv[i]); return 2; }
        const char *v = argv[++i];
        if (!strcmp(k, "port")) port = atoi(v);
        else if (!strcmp(k, "cert")) cert = v;
        else if (!strcmp(k, "key")) key = v;
        else if (!strcmp(k, "cert_chain")) chain = v;
        else if (!strcmp(k, "groups")) groups = v;
        else if (!strcmp(k, "payload")) payload = v;
        else if (!strcmp(k, "tickets")) ntickets = atoi(v);
        else if (!strcmp(k, "cert_comp")) cert_comp = v;
        else { fprintf(stderr, "option inconnue: %s\n", argv[i - 1]); return 2; }
    }
    if (cert == NULL || key == NULL) { fprintf(stderr, "usage: -cert F -key F [...]\n"); return 2; }

    signal(SIGPIPE, SIG_IGN);
    OPENSSL_init_ssl(0, NULL);
    g_ctx = SSL_CTX_new(TLS_server_method());
    if (g_ctx == NULL) { ERR_print_errors_fp(stderr); return 1; }
    SSL_CTX_set_min_proto_version(g_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(g_ctx, TLS1_3_VERSION);
    SSL_CTX_set_num_tickets(g_ctx, (size_t)ntickets);
    if (ntickets == 0)
        SSL_CTX_set_session_cache_mode(g_ctx, SSL_SESS_CACHE_OFF);
    if (groups != NULL && !SSL_CTX_set1_groups_list(g_ctx, groups)) {
        fprintf(stderr, "groupes invalides: %s\n", groups); ERR_print_errors_fp(stderr); return 1;
    }
    if (SSL_CTX_use_certificate_file(g_ctx, cert, SSL_FILETYPE_PEM) <= 0
        || SSL_CTX_use_PrivateKey_file(g_ctx, key, SSL_FILETYPE_PEM) <= 0
        || !SSL_CTX_check_private_key(g_ctx)) {
        fprintf(stderr, "certificat/cle invalides\n"); ERR_print_errors_fp(stderr); return 1;
    }
    if (chain != NULL) {
        /* Equivalent de `s_server -cert_chain` : l'intermediaire est envoye apres la feuille. */
        BIO *cb = BIO_new_file(chain, "r");
        X509 *x;
        if (cb == NULL) { fprintf(stderr, "cert_chain illisible: %s\n", chain); return 1; }
        while ((x = PEM_read_bio_X509(cb, NULL, NULL, NULL)) != NULL) {
            if (!SSL_CTX_add_extra_chain_cert(g_ctx, x)) { fprintf(stderr, "add_extra_chain_cert\n"); return 1; }
        }
        ERR_clear_error();
        BIO_free(cb);
    }
    if (cert_comp != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L && !defined(OPENSSL_NO_COMP_ALG)
        if (!strcmp(cert_comp, "none")) {
            SSL_CTX_set_options(g_ctx, SSL_OP_NO_RX_CERTIFICATE_COMPRESSION | SSL_OP_NO_TX_CERTIFICATE_COMPRESSION);
        } else {
            int alg = !strcmp(cert_comp, "zlib") ? TLSEXT_comp_cert_zlib
                    : !strcmp(cert_comp, "brotli") ? TLSEXT_comp_cert_brotli
                    : !strcmp(cert_comp, "zstd") ? TLSEXT_comp_cert_zstd : -1;
            if (alg < 0 || !SSL_CTX_set1_cert_comp_preference(g_ctx, &alg, 1)) {
                fprintf(stderr, "compression de certificat '%s' indisponible\n", cert_comp); return 1;
            }
            /* OpenSSL (>= 3.2) n'envoie un Certificate compresse (type 25) que si le serveur a PRE-COMPRESSE la chaine :
             * il n'y a pas de compression a la volee. Si la compression ne reduit pas la taille (cas des cles et signatures
             * ML-DSA, quasi aleatoires), OpenSSL renvoie 0 : ce n'est pas une erreur, le serveur enverra la chaine telle
             * quelle (c'est precisement ce que l'on veut mesurer). On le journalise. */
            ERR_clear_error();
            if (SSL_CTX_compress_certs(g_ctx, alg))
                fprintf(stderr, "tls_mt_server: chaine pre-compressee (%s)\n", cert_comp);
            else
                fprintf(stderr, "tls_mt_server: PAS de gain avec %s : la chaine sera envoyee NON compressee\n", cert_comp);
            ERR_clear_error();
        }
#else
        if (strcmp(cert_comp, "none")) { fprintf(stderr, "compression de certificat non supportee par cette build\n"); return 1; }
#endif
    }
    if (payload != NULL) {
        FILE *f = fopen(payload, "rb");
        if (f == NULL) { fprintf(stderr, "payload illisible: %s\n", payload); return 1; }
        g_payload_len = fread(g_payload, 1, PAYLOAD_MAX, f);
        fclose(f);
    } else {
        memset(g_payload, 0xA5, g_payload_len);
    }

    int ls = socket(AF_INET6, SOCK_STREAM, 0), one = 1, off = 0;
    if (ls >= 0) {                                   /* double pile IPv6/IPv4, comme `s_server -accept 4433` */
        struct sockaddr_in6 a6;
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        setsockopt(ls, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        memset(&a6, 0, sizeof(a6));
        a6.sin6_family = AF_INET6;
        a6.sin6_addr = in6addr_any;
        a6.sin6_port = htons((uint16_t)port);
        if (bind(ls, (struct sockaddr *)&a6, sizeof(a6)) < 0 || listen(ls, 4096) < 0) { perror("bind/listen (IPv6)"); return 1; }
    } else {                                         /* noyau sans IPv6 : repli IPv4 */
        struct sockaddr_in a4;
        ls = socket(AF_INET, SOCK_STREAM, 0);
        if (ls < 0) { perror("socket"); return 1; }
        setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        memset(&a4, 0, sizeof(a4));
        a4.sin_family = AF_INET;
        a4.sin_addr.s_addr = htonl(INADDR_ANY);
        a4.sin_port = htons((uint16_t)port);
        if (bind(ls, (struct sockaddr *)&a4, sizeof(a4)) < 0 || listen(ls, 4096) < 0) { perror("bind/listen (IPv4)"); return 1; }
    }
    fprintf(stderr, "tls_mt_server: ecoute sur :%d (tickets=%d, comp=%s)\n", port, ntickets, cert_comp ? cert_comp : "default");

    for (;;) {
        int fd = accept(ls, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            perror("accept"); usleep(1000); continue;
        }
        conn_arg *a = (conn_arg *)malloc(sizeof(*a));
        pthread_t th;
        pthread_attr_t at;
        if (a == NULL) { close(fd); continue; }
        a->fd = fd;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&at, 1 << 20);     /* 1 Mio : les cles HQC/ML-KEM utilisent de grands tableaux locaux */
        if (pthread_create(&th, &at, serve, a) != 0) { close(fd); free(a); }
        pthread_attr_destroy(&at);
    }
    return 0;
}
