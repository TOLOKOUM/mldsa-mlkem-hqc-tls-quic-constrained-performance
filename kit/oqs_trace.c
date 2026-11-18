/* oqs_trace.c -- LD_PRELOAD : compte et chronometre (CPU du thread) les appels OQS_KEM_keypair / encaps / decaps de liboqs
 * (revue du 15/11/2026, point 4). Un fichier par processus : $OQS_TRACE_OUT.<comm>.<pid>.csv  (comm = nom du processus ; le role
 * client/serveur se deduit du processus : s_server / s_client / msquic server...). Colonnes : kem,fonction,appels,cpu_ns_total,wall_ns_total.
 * Limite : n'intercepte que si oqs-provider / MsQuic lient liboqs DYNAMIQUEMENT (verifier : ldd, ou nm -D). Si liboqs est statique,
 * utiliser un point d'arret gdb/uprobe sur les memes symboles. Surcout : deux clock_gettime par appel (<1 us), negligeable devant HQC.
 * Compilation : gcc -O2 -fPIC -shared -o liboqs_trace.so oqs_trace.c -ldl
 * Usage : OQS_TRACE_OUT=/tmp/trace LD_PRELOAD=$PWD/liboqs_trace.so openssl s_server ... */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

typedef struct { const char *method_name; } oqs_kem_head;   /* premier champ de OQS_KEM */
#define NSLOT 64
static struct { char kem[48]; int fn; unsigned long long n, cpu, wall; } slot[NSLOT];
static int nslot = 0;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static const char *FN[3] = {"keypair", "encaps", "decaps"};

static unsigned long long ts(clockid_t c) { struct timespec t; clock_gettime(c, &t); return (unsigned long long)t.tv_sec * 1000000000ULL + t.tv_nsec; }
static void rec(const char *kem, int fn, unsigned long long cpu, unsigned long long wall) {
    pthread_mutex_lock(&mu);
    int i; for (i = 0; i < nslot; i++) if (slot[i].fn == fn && !strcmp(slot[i].kem, kem)) break;
    if (i == nslot && nslot < NSLOT) { strncpy(slot[i].kem, kem, 47); slot[i].fn = fn; nslot++; }
    if (i < NSLOT) { slot[i].n++; slot[i].cpu += cpu; slot[i].wall += wall; }
    pthread_mutex_unlock(&mu);
}
#define WRAP(NAME, IDX, PROTO, ARGS) \
int NAME PROTO { static int (*real) PROTO = NULL; if (!real) real = dlsym(RTLD_NEXT, #NAME); \
    unsigned long long c0 = ts(CLOCK_THREAD_CPUTIME_ID), w0 = ts(CLOCK_MONOTONIC); int r = real ARGS; \
    rec(kem && ((oqs_kem_head *)kem)->method_name ? ((oqs_kem_head *)kem)->method_name : "?", IDX, ts(CLOCK_THREAD_CPUTIME_ID) - c0, ts(CLOCK_MONOTONIC) - w0); return r; }
WRAP(OQS_KEM_keypair, 0, (const void *kem, unsigned char *pk, unsigned char *sk), (kem, pk, sk))
WRAP(OQS_KEM_encaps, 1, (const void *kem, unsigned char *ct, unsigned char *ss, const unsigned char *pk), (kem, ct, ss, pk))
WRAP(OQS_KEM_decaps, 2, (const void *kem, unsigned char *ss, const unsigned char *ct, const unsigned char *sk), (kem, ss, ct, sk))

__attribute__((destructor)) static void dump(void) {
    const char *base = getenv("OQS_TRACE_OUT"); if (!base || !nslot) return;
    char comm[32] = "proc"; FILE *f = fopen("/proc/self/comm", "r"); if (f) { if (fgets(comm, sizeof comm, f)) comm[strcspn(comm, "\n")] = 0; fclose(f); }
    char path[512]; snprintf(path, sizeof path, "%s.%s.%d.csv", base, comm, (int)getpid());
    f = fopen(path, "w"); if (!f) return;
    fprintf(f, "kem,fonction,appels,cpu_ns_total,wall_ns_total\n");
    for (int i = 0; i < nslot; i++) fprintf(f, "%s,%s,%llu,%llu,%llu\n", slot[i].kem, FN[slot[i].fn], slot[i].n, slot[i].cpu, slot[i].wall);
    fclose(f);
}
