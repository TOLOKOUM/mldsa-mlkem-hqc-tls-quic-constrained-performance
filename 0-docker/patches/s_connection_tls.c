/*
 * Copyright 1995-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/opensslconf.h>

#ifndef OPENSSL_NO_SOCK

#include "apps.h"
#include "progs.h"
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include "s_apps.h"
#include <openssl/err.h>
#include "internal/sockets.h"
#if !defined(OPENSSL_SYS_MSDOS)
# include <unistd.h>
#endif

#define SSL_CONNECT_NAME        "localhost:4433"

#define SECONDS 30
#define SECONDSSTR "30"

static SSL *doConnection(SSL *scon, const char *host, SSL_CTX *ctx);

/*
 * ── Harmonisation TLS/QUIC (critique 4 de l'AE, TDSC-2026-09-3862) ──────────
 * APP_BODY_EXPECTED doit rester EGAL a SendBufferLength de s_connection_quic.c
 * et s_server_quic.c (100 octets) : c'est le critere de fin COMMUN
 * "reponse applicative complete recue", identique des deux cotes.
 */
#define APP_BODY_EXPECTED 100

/* Horloge MONOTONE (insensible aux sauts NTP/RTC, contrairement a gettimeofday). */
static double elapsed_ms(const struct timespec *a, const struct timespec *b)
{
    return (b->tv_sec - a->tv_sec) * 1000.0 + (b->tv_nsec - a->tv_nsec) / 1e6;
}

/*
 * Analyse tampon de reponse recu. Retourne :
 *    1 : reponse complete (>= APP_BODY_EXPECTED octets de CORPS recus)
 *    0 : incomplete, continuer a lire
 *   -1 : reponse invalide (statut HTTP != 200)
 * *body_len = nombre d'octets de corps deja recus.
 * "openssl s_server -WWW" peut repondre avec ou sans en-tete HTTP : les deux
 * formes sont gerees, le corps seul est compte (=> comparable au buffer QUIC).
 */
static int app_response_status(const char *resp, size_t len, size_t *body_len)
{
    size_t i, body_off = 0;

    *body_len = 0;
    if (len < 5)
        return 0;
    if (memcmp(resp, "HTTP/", 5) == 0) {
        int found = 0;
        for (i = 0; i + 3 < len; i++) {
            if (memcmp(resp + i, "\r\n\r\n", 4) == 0) {
                body_off = i + 4;
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
        if (len < 12 || memcmp(resp + 8, " 200", 4) != 0)
            return -1;
    }
    *body_len = len - body_off;
    return (*body_len >= APP_BODY_EXPECTED) ? 1 : 0;
}

/*
 * Define a HTTP get command globally.
 * Also define the size of the command, this is two bytes less than
 * the size of the string because the %s is replaced by the URL.
 */
static const char fmt_http_get_cmd[] = "GET %s HTTP/1.0\r\n\r\n";
static const size_t fmt_http_get_cmd_size = sizeof(fmt_http_get_cmd) - 2;

typedef enum OPTION_choice {
    OPT_COMMON,
    OPT_CONNECT, OPT_CIPHER, OPT_CIPHERSUITES, OPT_CERT, OPT_NAMEOPT, OPT_KEY,
    OPT_CAPATH, OPT_CAFILE, OPT_CASTORE,
    OPT_NOCAPATH, OPT_NOCAFILE, OPT_NOCASTORE,
    OPT_NEW, OPT_BUGS, OPT_VERIFY, OPT_SSL3,
    OPT_WWW, OPT_TLS1, OPT_TLS1_1, OPT_TLS1_2, OPT_TLS1_3,
    OPT_PROV_ENUM
} OPTION_CHOICE;

const OPTIONS s_connection_options[] = {
    OPT_SECTION("General"),
    {"help", OPT_HELP, '-', "Display this summary"},

    OPT_SECTION("Connection"),
    {"connect", OPT_CONNECT, 's',
     "Where to connect as post:port (default is " SSL_CONNECT_NAME ")"},
    {"new", OPT_NEW, '-', "Just time new connections"},
    {"bugs", OPT_BUGS, '-', "Turn on SSL bug compatibility"},
    {"cipher", OPT_CIPHER, 's', "TLSv1.2 and below cipher list to be used"},
    {"ciphersuites", OPT_CIPHERSUITES, 's',
     "Specify TLSv1.3 ciphersuites to be used"},
#ifndef OPENSSL_NO_SSL3
    {"ssl3", OPT_SSL3, '-', "Just use SSLv3"},
#endif
#ifndef OPENSSL_NO_TLS1
    {"tls1", OPT_TLS1, '-', "Just use TLSv1.0"},
#endif
#ifndef OPENSSL_NO_TLS1_1
    {"tls1_1", OPT_TLS1_1, '-', "Just use TLSv1.1"},
#endif
#ifndef OPENSSL_NO_TLS1_2
    {"tls1_2", OPT_TLS1_2, '-', "Just use TLSv1.2"},
#endif
#ifndef OPENSSL_NO_TLS1_3
    {"tls1_3", OPT_TLS1_3, '-', "Just use TLSv1.3"},
#endif
    {"verify", OPT_VERIFY, 'p',
     "Turn on peer certificate verification, set depth"},
    {"www", OPT_WWW, 's', "Fetch specified page from the site"},

    OPT_SECTION("Certificate"),
    {"nameopt", OPT_NAMEOPT, 's', "Certificate subject/issuer name printing options"},
    {"cert", OPT_CERT, '<', "Cert file to use, PEM format assumed"},
    {"key", OPT_KEY, '<', "File with key, PEM; default is -cert file"},
    {"cafile", OPT_CAFILE, '<', "PEM format file of CA's"},
    {"CAfile", OPT_CAFILE, '<', "PEM format file of CA's"},
    {"CApath", OPT_CAPATH, '/', "PEM format directory of CA's"},
    {"CAstore", OPT_CASTORE, ':', "URI to store of CA's"},
    {"no-CAfile", OPT_NOCAFILE, '-',
     "Do not load the default certificates file"},
    {"no-CApath", OPT_NOCAPATH, '-',
     "Do not load certificates from the default certificates directory"},
    {"no-CAstore", OPT_NOCASTORE, '-',
     "Do not load certificates from the default certificates store URI"},

    OPT_PROV_OPTIONS,
    {NULL}
};

#define START   0
#define STOP    1

int s_connection_main(int argc, char **argv)
{
    char buf[1024 * 8];
    SSL *scon = NULL;
    SSL_CTX *ctx = NULL;
    const SSL_METHOD *meth = NULL;
    char *CApath = NULL, *CAfile = NULL, *CAstore = NULL;
    char *cipher = NULL, *ciphersuites = NULL;
    char *www_path = NULL;
    char *host = SSL_CONNECT_NAME, *certfile = NULL, *keyfile = NULL, *prog;
    int noCApath = 0, noCAfile = 0, noCAstore = 0;
    int ret = 1, i, st_bugs = 0;
    long bytes_read = 0;
    OPTION_CHOICE o;
    int min_version = 0, max_version = 0, buf_len;
    size_t buf_size;
    struct timespec starttime, endtime, app_endtime;

    meth = TLS_client_method();

    prog = opt_init(argc, argv, s_connection_options);
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_EOF:
        case OPT_ERR:
 opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto end;
        case OPT_HELP:
            opt_help(s_connection_options);
            ret = 0;
            goto end;
        case OPT_CONNECT:
            host = opt_arg();
            break;
        case OPT_VERIFY:
            verify_args.depth = opt_int_arg();
            BIO_printf(bio_err, "%s: verify depth is %d\n",
                       prog, verify_args.depth);
            break;
        case OPT_CERT:
            certfile = opt_arg();
            break;
        case OPT_NAMEOPT:
            if (!set_nameopt(opt_arg()))
                goto end;
            break;
        case OPT_KEY:
            keyfile = opt_arg();
            break;
        case OPT_CAPATH:
            CApath = opt_arg();
            break;
        case OPT_CAFILE:
            CAfile = opt_arg();
            break;
        case OPT_NOCAPATH:
            noCApath = 1;
            break;
        case OPT_NOCAFILE:
            noCAfile = 1;
            break;
        case OPT_CASTORE:
            CAstore = opt_arg();
            break;
        case OPT_NOCASTORE:
            noCAstore = 1;
            break;
        case OPT_CIPHER:
            cipher = opt_arg();
            break;
        case OPT_CIPHERSUITES:
            ciphersuites = opt_arg();
            break;
        case OPT_BUGS:
            st_bugs = 1;
            break;
        case OPT_WWW:
            www_path = opt_arg();
            buf_size = strlen(www_path) + fmt_http_get_cmd_size;
            if (buf_size > sizeof(buf)) {
                BIO_printf(bio_err, "%s: -www option is too long\n", prog);
                goto end;
            }
            break;
        case OPT_SSL3:
            min_version = SSL3_VERSION;
            max_version = SSL3_VERSION;
            break;
        case OPT_TLS1:
            min_version = TLS1_VERSION;
            max_version = TLS1_VERSION;
            break;
        case OPT_TLS1_1:
            min_version = TLS1_1_VERSION;
            max_version = TLS1_1_VERSION;
            break;
        case OPT_TLS1_2:
            min_version = TLS1_2_VERSION;
            max_version = TLS1_2_VERSION;
            break;
        case OPT_TLS1_3:
            min_version = TLS1_3_VERSION;
            max_version = TLS1_3_VERSION;
            break;
        case OPT_PROV_CASES:
            if (!opt_provider(o))
                goto end;
            break;
        }
    }

    /* No extra arguments. */
    if (!opt_check_rest_arg(NULL))
        goto opthelp;

    if (cipher == NULL)
        cipher = getenv("SSL_CIPHER");

    if ((ctx = SSL_CTX_new(meth)) == NULL)
        goto end;

    SSL_CTX_set_quiet_shutdown(ctx, 1);
    if (SSL_CTX_set_min_proto_version(ctx, min_version) == 0)
        goto end;
    if (SSL_CTX_set_max_proto_version(ctx, max_version) == 0)
        goto end;

    if (st_bugs)
        SSL_CTX_set_options(ctx, SSL_OP_ALL);
    if (cipher != NULL && !SSL_CTX_set_cipher_list(ctx, cipher))
        goto end;
    if (ciphersuites != NULL && !SSL_CTX_set_ciphersuites(ctx, ciphersuites))
        goto end;
    if (!set_cert_stuff(ctx, certfile, keyfile))
        goto end;

    if (!ctx_set_verify_locations(ctx, CAfile, noCAfile, CApath, noCApath,
                                  CAstore, noCAstore)) {
        ERR_print_errors(bio_err);
        goto end;
    }

    /*
     * "-verify <depth>" doit etre EFFECTIF : sans SSL_CTX_set_verify() le client est en
     * SSL_VERIFY_NONE (valeur par defaut) -- la chaine est calculee mais un echec de
     * verification n'interrompt pas le handshake, alors que MsQuic (CA file) l'interrompt.
     * Le cout cryptographique est identique ; seule la politique d'acceptation change.
     * ATTENTION : le callback standard des apps OpenSSL ignore les erreurs de verification tant que
     * verify_args.return_error vaut 0 (equivalent de -verify_return_error) ; d'ou la ligne ci-dessous.
     */
    verify_args.return_error = 1;   /* sinon verify_callback() transforme toute erreur en succes (ok=1) */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    if (verify_args.depth >= 0)
        SSL_CTX_set_verify_depth(ctx, verify_args.depth);

    /* Mesure de la duree de connexion (TCP connect + handshake TLS) */
    clock_gettime(CLOCK_MONOTONIC, &starttime);
    if ((scon = doConnection(NULL, host, ctx)) == NULL)
        goto end;
    clock_gettime(CLOCK_MONOTONIC, &endtime);

    /*
     * Metrique PRINCIPALE commune TLS/QUIC : "App-ready duration" =
     *   t(reponse applicative COMPLETE recue) - t(debut de connexion).
     * "Handshake duration" (timer natif) reste une metrique SECONDAIRE.
     *
     * Regles identiques cote QUIC (s_connection_quic.c) :
     *  - la mesure s'arrete des que APP_BODY_EXPECTED octets de corps sont
     *    recus (PAS d'attente de l'EOF/fermeture serveur, qui gonflerait TLS
     *    seul sous perte : -WWW repond en HTTP/1.0 puis ferme) ;
     *  - une reponse invalide, tronquee ou un reset => "App-ready: NaN" ;
     *  - horloge CLOCK_MONOTONIC des deux cotes.
     */
    if (www_path != NULL) {
        char resp[1024];
        size_t resp_len = 0, body_len = 0;
        int st = 0;
        int app_ok = 0;

        buf_len = BIO_snprintf(buf, sizeof(buf), fmt_http_get_cmd,
                                www_path);
        if (buf_len > 0 && SSL_write(scon, buf, buf_len) > 0) {
            while (resp_len < sizeof(resp)) {
                i = SSL_read(scon, resp + resp_len, (int)(sizeof(resp) - resp_len));
                if (i <= 0)
                    break;
                resp_len += (size_t)i;
                bytes_read += i;
                st = app_response_status(resp, resp_len, &body_len);
                if (st != 0)
                    break;
            }
            if (st == 1) {
                clock_gettime(CLOCK_MONOTONIC, &app_endtime);
                app_ok = 1;
            }
        }
        if (!app_ok) {
            printf("Handshake duration: %.2f ms\n", elapsed_ms(&starttime, &endtime));
            printf("App-ready duration: NaN ms  (application response %s)\n",
                   st < 0 ? "invalid status" : "incomplete or request failed");
            goto end;
        }
        printf("App-bytes: %zu\n", body_len);
    }
    SSL_set_shutdown(scon, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
    BIO_closesocket(SSL_get_fd(scon));

    SSL_free(scon);
    scon = NULL;

    printf("Handshake duration: %.2f ms\n", elapsed_ms(&starttime, &endtime));

    if (www_path != NULL)
        printf("App-ready duration: %.2f ms\n", elapsed_ms(&starttime, &app_endtime));
    ret = 0;

 end:
    SSL_free(scon);
    SSL_CTX_free(ctx);
    return ret;
}

/*-
 * doConnection - make a connection
 */
static SSL *doConnection(SSL *scon, const char *host, SSL_CTX *ctx)
{
    BIO *conn;
    SSL *serverCon;
    int i;

    if ((conn = BIO_new(BIO_s_connect())) == NULL)
        return NULL;

    if (BIO_set_conn_hostname(conn, host) <= 0
            || BIO_set_conn_mode(conn, BIO_SOCK_NODELAY) <= 0) {
        BIO_free(conn);
        return NULL;
    }

    if (scon == NULL) {
        serverCon = SSL_new(ctx);
        if (serverCon == NULL) {
            BIO_free(conn);
            return NULL;
        }
    } else {
        serverCon = scon;
        SSL_set_connect_state(serverCon);
    }

    SSL_set_bio(serverCon, conn, conn);

    /* ok, lets connect */
    i = SSL_connect(serverCon);
    if (i <= 0) {
        BIO_printf(bio_err, "ERROR\n");
        if (verify_args.error != X509_V_OK)
            BIO_printf(bio_err, "verify error:%s\n",
                       X509_verify_cert_error_string(verify_args.error));
        else
            ERR_print_errors(bio_err);
        if (scon == NULL)
            SSL_free(serverCon);
        return NULL;
    }

#if defined(SOL_SOCKET) && defined(SO_LINGER)
    {
        struct linger no_linger;
        int fd;

        no_linger.l_onoff  = 1;
        no_linger.l_linger = 0;
        fd = SSL_get_fd(serverCon);
        if (fd >= 0)
            (void)setsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&no_linger,
                             sizeof(no_linger));
    }
#endif

    return serverCon;
}
#endif /* OPENSSL_NO_SOCK */
