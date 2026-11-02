/*
 * tls_load_client.c -- generateur de charge TLS 1.3 PERSISTANT, multi-fils, en boucle fermee (campagne v3, bras charge).
 *
 * POURQUOI : le pilote du 27/10/2026 a montre que le client "un processus openssl s_connection par connexion" coute 50-120 ms de CPU
 * par connexion (demarrage du processus, chargement d'oqsprovider) contre 3-4 ms cote serveur en ML-KEM : le generateur, pas le serveur,
 * saturait. Ici UN processus, c fils, chacun enchaine des connexions COMPLETES (TCP + handshake TLS 1.3 + requete applicative) sans
 * temps de reflexion pendant -seconds secondes. Le cout par connexion cote client se reduit au handshake lui-meme.
 *
 * MESURES (memes definitions que s_connection_tls.c) : hs_ms = de la creation du socket a la fin de SSL_connect ;
 * app_ms = jusqu'a la reception de 100 octets de corps de la reponse a "GET <path> HTTP/1.0" ; rx = octets lus sur la socket
 * pendant le handshake. Horloge CLOCK_MONOTONIC pour les durees, CLOCK_REALTIME (ms epoch) pour t_end.
 *
 * SORTIE (stdout, a la fin) : une ligne par connexion
 *   LOADCONN conc=<c> worker=<w> t_end=<epoch_ms> ok=<0|1> hs_ms=<..|NaN> app_ms=<..|NaN> rx=<octets|NA>
 * et, sur stderr, un resume. Format lu par perftestLoadClient.sh / 13_analyse_extensions.py.
 *
 * USAGE : tls_load_client -connect host:4433 -CAfile CA.crt -groups G -conc 8 -seconds 20 [-www /payload.bin]
 *                         [-timeout_s 30] [-cert_comp none|zlib|brotli|zstd] [-verify_depth 1]
 * Compilation : gcc -O2 -pthread -Wall -o tls_load_client tls_load_client.c -lssl -lcrypto
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define APP_BODY_EXPECTED 100

typedef struct { long long t_end_ms; int ok; double hs_ms, app_ms; long rx; } rec_t;
typedef struct { int id; rec_t *r; size_t n, cap; } worker_t;

static SSL_CTX *g_ctx;
static struct addrinfo *g_ai;
static const char *g_path = "/payload.bin";
static int g_conc = 1, g_timeout_s = 30;
static double g_seconds = 20.0;
static struct timespec g_deadline;   /* monotone */

static double ms_between(const struct timespec *a, const struct timespec *b)
{
    return (b->tv_sec - a->tv_sec) * 1000.0 + (b->tv_nsec - a->tv_nsec) / 1e6;
}
static long long realtime_ms(void)
{
    struct timespec t; clock_gettime(CLOCK_REALTIME, &t);
    return (long long)t.tv_sec * 1000LL + t.tv_nsec / 1000000LL;
}

/* Meme criterion que s_connection_tls.c : 1 = reponse complete, 0 = incomplete, -1 = invalide. */
static int app_status(const char *resp, size_t len, size_t *body_len)
{
    size_t i, off = 0;
    *body_len = 0;
    if (len < 5) return 0;
    if (memcmp(resp, "HTTP/", 5) == 0) {
        int found = 0;
        for (i = 0; i + 3 < len; i++)
            if (memcmp(resp + i, "\r\n\r\n", 4) == 0) { off = i + 4; found = 1; break; }
        if (!found) return 0;
        if (len < 12 || memcmp(resp + 8, " 200", 4) != 0) return -1;
    }
    *body_len = len - off;
    return (*body_len >= APP_BODY_EXPECTED) ? 1 : 0;
}

static int one_connection(rec_t *out)
{
    struct timespec t0, t1, t2;
    int fd = -1, rc = 0;
    SSL *ssl = NULL;
    char req[256], resp[1024];
    size_t rl = 0, body = 0;
    int st = 0;

    memset(out, 0, sizeof(*out));
    out->hs_ms = out->app_ms = -1; out->rx = -1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    fd = socket(g_ai->ai_family, SOCK_STREAM, 0);
    if (fd < 0) goto done;
    {
        int one = 1; struct timeval tv = { g_timeout_s, 0 };
        struct linger lg = { 1, 0 };
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg));   /* comme s_connection : fermeture par RST, pas de TIME_WAIT */
    }
    if (connect(fd, g_ai->ai_addr, g_ai->ai_addrlen) != 0) goto done;
    ssl = SSL_new(g_ctx);
    if (ssl == NULL) goto done;
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) <= 0) { ERR_clear_error(); goto done; }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    out->rx = (long)BIO_number_read(SSL_get_rbio(ssl));
    rl = (size_t)snprintf(req, sizeof(req), "GET %s HTTP/1.0\r\n\r\n", g_path);
    if (SSL_write(ssl, req, (int)rl) <= 0) goto done;
    rl = 0;
    while (rl < sizeof(resp)) {
        int i = SSL_read(ssl, resp + rl, (int)(sizeof(resp) - rl));
        if (i <= 0) break;
        rl += (size_t)i;
        st = app_status(resp, rl, &body);
        if (st != 0) break;
    }
    if (st != 1) goto done;
    clock_gettime(CLOCK_MONOTONIC, &t2);
    out->hs_ms = ms_between(&t0, &t1);
    out->app_ms = ms_between(&t0, &t2);
    rc = 1;
done:
    out->ok = rc;
    out->t_end_ms = realtime_ms();
    if (ssl != NULL) { SSL_set_quiet_shutdown(ssl, 1); SSL_free(ssl); }   /* SSL_free ne ferme pas la socket : fd ferme ci-dessous */
    if (fd >= 0) close(fd);
    return rc;
}

static void *worker_main(void *arg)
{
    worker_t *w = (worker_t *)arg;
    for (;;) {
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        if (ms_between(&now, &g_deadline) <= 0) break;
        if (w->n == w->cap) {
            w->cap = w->cap ? w->cap * 2 : 4096;
            w->r = realloc(w->r, w->cap * sizeof(rec_t));
            if (w->r == NULL) { fprintf(stderr, "memoire insuffisante\n"); exit(2); }
        }
        one_connection(&w->r[w->n]);
        w->n++;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *host = NULL, *port = "4433", *cafile = NULL, *groups = getenv("DEFAULT_GROUPS"), *cert_comp = NULL;
    int depth = 1, i;
    char hbuf[256];

    for (i = 1; i + 1 < argc; i += 2) {
        const char *k = argv[i] + (argv[i][0] == '-' ? 1 : 0), *v = argv[i + 1];
        if (!strcmp(k, "connect")) { snprintf(hbuf, sizeof(hbuf), "%s", v); host = hbuf; }
        else if (!strcmp(k, "CAfile")) cafile = v;
        else if (!strcmp(k, "groups")) groups = v;
        else if (!strcmp(k, "conc")) g_conc = atoi(v);
        else if (!strcmp(k, "seconds")) g_seconds = atof(v);
        else if (!strcmp(k, "www")) g_path = v;
        else if (!strcmp(k, "timeout_s")) g_timeout_s = atoi(v);
        else if (!strcmp(k, "cert_comp")) cert_comp = v;
        else if (!strcmp(k, "verify_depth")) depth = atoi(v);
        else { fprintf(stderr, "option inconnue: %s\n", argv[i]); return 2; }
    }
    if (host == NULL || cafile == NULL || g_conc < 1) {
        fprintf(stderr, "usage: %s -connect host:port -CAfile CA.crt [-groups G] -conc N -seconds S [-www /payload.bin]\n", argv[0]);
        return 2;
    }
    {   /* host:port */
        char *c = strrchr(hbuf, ':');
        if (c != NULL) { *c = '\0'; port = c + 1; }
        struct addrinfo hints; memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        int gai = getaddrinfo(hbuf[0] ? hbuf : "localhost", port, &hints, &g_ai);
        if (gai != 0 || g_ai == NULL) { fprintf(stderr, "getaddrinfo(%s): %s\n", hbuf, gai_strerror(gai)); return 2; }
    }
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, NULL);
    g_ctx = SSL_CTX_new(TLS_client_method());
    if (g_ctx == NULL) { ERR_print_errors_fp(stderr); return 2; }
    SSL_CTX_set_min_proto_version(g_ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(g_ctx, TLS1_3_VERSION);
    if (!SSL_CTX_load_verify_locations(g_ctx, cafile, NULL)) { fprintf(stderr, "CAfile illisible: %s\n", cafile); ERR_print_errors_fp(stderr); return 2; }
    SSL_CTX_set_verify(g_ctx, SSL_VERIFY_PEER, NULL);          /* equivalent de s_connection -verify 1 -verify_return_error */
    SSL_CTX_set_verify_depth(g_ctx, depth);
    SSL_CTX_set_session_cache_mode(g_ctx, SSL_SESS_CACHE_OFF);  /* aucune reprise : connexions COMPLETES */
    if (groups != NULL && *groups && !SSL_CTX_set1_groups_list(g_ctx, groups)) {
        fprintf(stderr, "groupes invalides: %s\n", groups); ERR_print_errors_fp(stderr); return 2;
    }
    if (cert_comp != NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x30200000L && !defined(OPENSSL_NO_COMP_ALG)
        if (!strcmp(cert_comp, "none")) SSL_CTX_set_options(g_ctx, SSL_OP_NO_RX_CERTIFICATE_COMPRESSION | SSL_OP_NO_TX_CERTIFICATE_COMPRESSION);
        else {
            int alg = !strcmp(cert_comp, "zlib") ? TLSEXT_comp_cert_zlib : !strcmp(cert_comp, "brotli") ? TLSEXT_comp_cert_brotli
                    : !strcmp(cert_comp, "zstd") ? TLSEXT_comp_cert_zstd : -1;
            if (alg < 0 || !SSL_CTX_set1_cert_comp_preference(g_ctx, &alg, 1)) { fprintf(stderr, "compression %s indisponible\n", cert_comp); return 2; }
        }
#else
        if (strcmp(cert_comp, "none") != 0) { fprintf(stderr, "compression non supportee par cette build\n"); return 2; }
#endif
    }
    signal(SIGPIPE, SIG_IGN);   /* une ecriture sur une connexion fermee ne doit pas tuer le generateur */

    clock_gettime(CLOCK_MONOTONIC, &g_deadline);
    g_deadline.tv_sec += (time_t)g_seconds;
    g_deadline.tv_nsec += (long)((g_seconds - (double)(time_t)g_seconds) * 1e9);
    if (g_deadline.tv_nsec >= 1000000000L) { g_deadline.tv_sec++; g_deadline.tv_nsec -= 1000000000L; }

    pthread_t *th = calloc((size_t)g_conc, sizeof(pthread_t));
    worker_t *ws = calloc((size_t)g_conc, sizeof(worker_t));
    for (i = 0; i < g_conc; i++) { ws[i].id = i + 1; pthread_create(&th[i], NULL, worker_main, &ws[i]); }
    for (i = 0; i < g_conc; i++) pthread_join(th[i], NULL);

    size_t tot = 0, bad = 0;
    for (i = 0; i < g_conc; i++) {
        for (size_t j = 0; j < ws[i].n; j++) {
            rec_t *r = &ws[i].r[j];
            tot++; if (!r->ok) bad++;
            if (r->ok) printf("LOADCONN conc=%d worker=%d t_end=%lld ok=1 hs_ms=%.3f app_ms=%.3f rx=%ld\n", g_conc, ws[i].id, r->t_end_ms, r->hs_ms, r->app_ms, r->rx);
            else       printf("LOADCONN conc=%d worker=%d t_end=%lld ok=0 hs_ms=NaN app_ms=NaN rx=NA\n", g_conc, ws[i].id, r->t_end_ms);
        }
    }
    fprintf(stderr, "tls_load_client: conc=%d connexions=%zu echecs=%zu\n", g_conc, tot, bad);
    return 0;
}
