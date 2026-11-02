/*
 * quics_load.c -- client QUIC de CHARGE persistant (campagne v3b). Compile a part (gcc, contre libmsquic.so de l'image) :
 * ce fichier est s_connection_quic.c (client de la campagne v3, INCHANGE) PLUS le mode charge (LOAD_CONC, LOAD_SECONDS,
 * LOAD_TIMEOUT_S) ; sans LOAD_CONC il se comporte exactement comme quics_connection. Le binaire quics_connection de l'image v3
 * n'est pas modifie : l'image v3b = image v3 + tls_load_client + quics_load + perftestLoadClient.sh.
 * Compilation : gcc -O2 -pthread quics_load.c -o quics_load -I<MsQuic>/src/inc -L<MsQuic>/build/bin/Release -lmsquic
 */
#include "msquic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <errno.h>


#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
//const QUIC_REGISTRATION_CONFIG RegConfig = { "quics_connection", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
const QUIC_REGISTRATION_CONFIG RegConfig = { "quics_connection", QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME };

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

//
// The UDP port used by the server side of the protocol. 
// It can be changed using the "-port" command line parameter.
//
uint16_t UdpPort = 4433;

//
// The default idle timeout period (1 second) used for the protocol.
//
const uint64_t IdleTimeoutMs = 100000;

//
// The length of buffer sent over the streams in the protocol.
//
const uint32_t SendBufferLength = 100;

//
// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
//
const QUIC_API_TABLE* MsQuic;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
HQUIC Registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
HQUIC Configuration;

QUIC_TLS_SECRETS ClientSecrets = {0};

const char* SslKeyLogEnvVar = "SSLKEYLOGFILE";

//
// The enviromment variable used to change the curve used in the handshake.
//
const char* GroupsListVar = "GROUPS_LIST";

//
// Flag to indicate if the loggers are enabled.
//
BOOLEAN VerboseEnabled = FALSE;

typedef struct {
    HQUIC Connection;
    double HandshakeDurationMs;
    BOOLEAN HandshakeMeasured;
    /*
     * Point 4 du prescreen TDSC (TDSC-2026-09-3862) : StartTime est capture
     * juste avant ConnectionStart() (voir main()), et AppReadyDurationMs
     * mesure jusqu'a la reception complete de la reponse applicative fixe
     * de 100 octets envoyee par quics_server (voir ClientSend/
     * ClientStreamCallback ci-dessous et ServerSend dans s_server_quic.c).
     * C'est la meme borne d'evenement que "App-ready duration" cote TLS
     * (apps/s_connection.c, openssl fork).
     */
    struct timespec StartTime;   /* CLOCK_MONOTONIC (comme cote TLS) */
    double AppReadyDurationMs;
    BOOLEAN AppReadyMeasured;
    uint32_t AppBytes;           /* octets de reponse recus (critere de fin commun) */
    /*
     * EXTENSIONS campagne v3 (reprise de session / 0-RTT / octets du handshake) :
     *  Resumed     : le serveur a accepte la reprise (Event->CONNECTED.SessionResumed)
     *  RxBytes/TxBytes : octets UDP recus / emis par le client AU MOMENT de l'evenement CONNECTED
     *                (= vol serveur du handshake + ACK ; analogue du compteur BIO cote TLS)
     *  TicketSaved : un ticket a ete ecrit dans $TICKET_OUT ; TicketBytes : sa taille
     *  SentEarly   : la requete applicative a ete envoyee en 0-RTT (avant CONNECTED)
     */
    BOOLEAN Resumed;
    uint64_t RxBytes;
    uint64_t TxBytes;
    BOOLEAN TicketSaved;
    uint32_t TicketBytes;
    BOOLEAN SentEarly;
} APP_CONNECTION_CTX;


void PrintUsage()
{
    printf(
        "\n"
        "quics_connection runs a simple benchmark tool implementing a QUIC client measuring the time of one connection to be used with quics_server.\n"
        "\n"
        "Usage:\n"
        "\n"
        "  quics_connection.exe -target:{IPAddress|Hostname} -port:<...> -groups:<...> -CAfile:<...> -unsecure -verbose -cert_file:<...> -key_file:<...> [-password:<...>]\n"
        );
}

//
// Helper functions to look up a command line arguments.
//
BOOLEAN
GetFlag(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
    )
{
    const size_t nameLen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0
            && strlen(argv[i]) == nameLen + 1) {
            return TRUE;
        }
    }
    return FALSE;
}

_Ret_maybenull_ _Null_terminated_ const char*
GetValue(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[],
    _In_z_ const char* name
    )
{
    const size_t nameLen = strlen(name);
    for (int i = 0; i < argc; i++) {
        if (_strnicmp(argv[i] + 1, name, nameLen) == 0
            && strlen(argv[i]) > 1 + nameLen + 1
            && *(argv[i] + 1 + nameLen) == ':') {
            return argv[i] + 1 + nameLen + 1;
        }
    }
    return NULL;
}

void
EncodeHexBuffer(
    _In_reads_(BufferLen) uint8_t* Buffer,
    _In_ uint8_t BufferLen,
    _Out_writes_bytes_(2*BufferLen) char* HexString
    )
{
    #define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    for (uint8_t i = 0; i < BufferLen; i++) {
        HexString[i*2]     = HEX_TO_CHAR(Buffer[i] >> 4);
        HexString[i*2 + 1] = HEX_TO_CHAR(Buffer[i] & 0xf);
    }
}

void
WriteSslKeyLogFile(
    _In_z_ const char* FileName,
    _In_ QUIC_TLS_SECRETS* TlsSecrets
    )
{
    printf("Writing SSLKEYLOGFILE at %s\n", FileName);
    FILE* File = NULL;
#ifdef _WIN32
    File = _fsopen(FileName, "ab", _SH_DENYNO);
#else
    File = fopen(FileName, "ab");
#endif

    if (File == NULL) {
        printf("Failed to open sslkeylogfile %s\n", FileName);
        return;
    }
    if (fseek(File, 0, SEEK_END) == 0 && ftell(File) == 0) {
        fprintf(File, "# TLS 1.3 secrets log file, generated by msquic\n");
    }

    char ClientRandomBuffer[(2 * sizeof(((QUIC_TLS_SECRETS*)0)->ClientRandom)) + 1] = {0};

    char TempHexBuffer[(2 * QUIC_TLS_SECRETS_MAX_SECRET_LEN) + 1] = {0};
    if (TlsSecrets->IsSet.ClientRandom) {
        EncodeHexBuffer(
            TlsSecrets->ClientRandom,
            (uint8_t)sizeof(TlsSecrets->ClientRandom),
            ClientRandomBuffer);
    }

    if (TlsSecrets->IsSet.ClientEarlyTrafficSecret) {
        EncodeHexBuffer(
            TlsSecrets->ClientEarlyTrafficSecret,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "CLIENT_EARLY_TRAFFIC_SECRET %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets->IsSet.ClientHandshakeTrafficSecret) {
        EncodeHexBuffer(
            TlsSecrets->ClientHandshakeTrafficSecret,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets->IsSet.ServerHandshakeTrafficSecret) {
        EncodeHexBuffer(
            TlsSecrets->ServerHandshakeTrafficSecret,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets->IsSet.ClientTrafficSecret0) {
        EncodeHexBuffer(
            TlsSecrets->ClientTrafficSecret0,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "CLIENT_TRAFFIC_SECRET_0 %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    if (TlsSecrets->IsSet.ServerTrafficSecret0) {
        EncodeHexBuffer(
            TlsSecrets->ServerTrafficSecret0,
            TlsSecrets->SecretLength,
            TempHexBuffer);
        fprintf(
            File,
            "SERVER_TRAFFIC_SECRET_0 %s %s\n",
            ClientRandomBuffer,
            TempHexBuffer);
    }

    fflush(File);
    fclose(File);
}

//
// The clients's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ClientStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    APP_CONNECTION_CTX* Ctx = (APP_CONNECTION_CTX*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream. Point 4 (TDSC
        // prescreen) : c'est l'evenement "application-ready" commun
        // TLS/QUIC. La reponse de quics_server est un buffer fixe de 100
        // octets envoye en un seul StreamSend avec QUIC_SEND_FLAG_FIN
        // (voir ServerSend, s_server_quic.c), donc cette premiere RECEIVE
        // correspond a la reponse complete -- pas de reassemblage
        // multi-evenements a gerer ici.
        //
        printf("[strm][%p] Data received\n", Stream);
        if (Ctx != NULL && !Ctx->AppReadyMeasured) {
            //
            // Critere de fin COMMUN avec TLS (s_connection_tls.c) : la mesure
            // s'arrete quand SendBufferLength (=APP_BODY_EXPECTED) octets de
            // reponse ont ete recus -- on cumule donc les octets au lieu de
            // supposer qu'un seul evenement RECEIVE porte toute la reponse.
            //
            Ctx->AppBytes += (uint32_t)Event->RECEIVE.TotalBufferLength;
            if (Ctx->AppBytes >= SendBufferLength) {
                struct timespec AppReadyTime;
                clock_gettime(CLOCK_MONOTONIC, &AppReadyTime);
                Ctx->AppReadyDurationMs =
                    (AppReadyTime.tv_sec - Ctx->StartTime.tv_sec) * 1000.0 +
                    (AppReadyTime.tv_nsec - Ctx->StartTime.tv_nsec) / 1e6;
                Ctx->AppReadyMeasured = TRUE;
                if (Ctx->Connection != NULL) {
                    MsQuic->ConnectionShutdown(Ctx->Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
                }
            }
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->StreamClose(Stream);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Point 4 du prescreen TDSC (TDSC-2026-09-3862) : desormais appelee depuis
// ClientConnectionCallback sur CONNECTED (au lieu d'un ConnectionShutdown
// immediat), pour produire un vrai echange applicatif mesurable des deux
// cotes TLS/QUIC. Ctx est propage au stream pour que ClientStreamCallback
// puisse y ecrire AppReadyDurationMs et declencher le shutdown une fois la
// reponse recue.
//

void
ClientSend(
    _In_ HQUIC Connection,
    _In_ APP_CONNECTION_CTX* Ctx,
    _In_ QUIC_SEND_FLAGS ExtraFlags
    )
{
    QUIC_STATUS Status;
    HQUIC Stream = NULL;
    uint8_t* SendBufferRaw;
    QUIC_BUFFER* SendBuffer;

    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, Ctx, &Stream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("[strm][%p] Starting...\n", Stream);

    //
    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", Status);
        MsQuic->StreamClose(Stream);
        goto Error;
    }

    //
    // Allocates and builds the buffer to send over the stream.
    //
    SendBufferRaw = (uint8_t*)malloc(sizeof(QUIC_BUFFER) + SendBufferLength);
    if (SendBufferRaw == NULL) {
        printf("SendBuffer allocation failed!\n");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }
    SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = SendBufferLength;
    memset(SendBuffer->Buffer, 0xA5, SendBufferLength);   // contenu deterministe

    printf("[strm][%p] Sending data...\n", Stream);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, (QUIC_SEND_FLAGS)(QUIC_SEND_FLAG_FIN | ExtraFlags), SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status)) {
        MsQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
}

//
// The clients's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ClientConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    //UNREFERENCED_PARAMETER(Context);
   APP_CONNECTION_CTX* Ctx = (APP_CONNECTION_CTX*)Context;

   if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {
        const char* SslKeyLogFile = getenv(SslKeyLogEnvVar);
        if (SslKeyLogFile != NULL) {
            WriteSslKeyLogFile(SslKeyLogFile, &ClientSecrets);
        }
    }

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        if(VerboseEnabled){
            printf("[conn][%p] Connected\n", Connection);
        }        
        QUIC_STATISTICS Stats = {0};
        uint32_t StatsLen = sizeof(Stats);
        
        if (QUIC_SUCCEEDED(MsQuic->GetParam(Connection, QUIC_PARAM_CONN_STATISTICS, &StatsLen, &Stats))) {
                double hs_duration = (Stats.Timing.HandshakeFlightEnd - Stats.Timing.Start) / 1000.0;

                if (hs_duration > 0 && hs_duration < 1000000) {
                    Ctx->HandshakeDurationMs = hs_duration;
                    Ctx->HandshakeMeasured = TRUE;
                    //printf("Handshake duration: %.2f ms\n", hs_duration);
                } 
                Ctx->RxBytes = Stats.Recv.TotalBytes;
                Ctx->TxBytes = Stats.Send.TotalBytes;
        } 
        Ctx->Resumed = Event->CONNECTED.SessionResumed;

        //
        // Point 4 du prescreen TDSC (TDSC-2026-09-3862) : au lieu d'un
        // ConnectionShutdown immediat apres le handshake, on echange un
        // message applicatif fixe pour mesurer "App-ready duration" --
        // le shutdown est desormais declenche depuis ClientStreamCallback
        // une fois la reponse recue (ou depuis le label Error de ClientSend
        // en cas d'echec de l'ouverture/l'envoi du flux).
        //
        if (!Ctx->SentEarly) {
            ClientSend(Connection, Ctx, QUIC_SEND_FLAG_NONE);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            if(VerboseEnabled){
                printf("[conn][%p] Successfully shut down on idle.\n", Connection);
            }
        } else {
            if(VerboseEnabled){
                printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
            }
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        if(VerboseEnabled){
            printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        if(VerboseEnabled){
            printf("[conn][%p] All done\n", Connection);
        }
        //QUIC_STATISTICS Stats = {0};
        //uint32_t StatsLen = sizeof(Stats);
        //if (QUIC_SUCCEEDED(MsQuic->GetParam(Connection, QUIC_PARAM_CONN_STATISTICS, &StatsLen, &Stats))) {
        //    printf("Handshake duration: %.2f ms\n", (Stats.Timing.HandshakeFlightEnd - Stats.Timing.Start) / 1000.0);
        //}

        if (Ctx->HandshakeMeasured) {
            printf("Handshake duration: %.2f ms\n", Ctx->HandshakeDurationMs);
        } else {
            printf("Handshake duration: NaN ms\n");
        }

        if (Ctx->AppReadyMeasured) {
            printf("App-bytes: %u\n", Ctx->AppBytes);
            printf("App-ready duration: %.2f ms\n", Ctx->AppReadyDurationMs);
        } else {
            printf("App-ready duration: NaN ms\n");
        }
        /* Lignes supplementaires de la campagne v3 (ignorees par les analyseurs de la campagne v2). */
        printf("Resumed: %d\n", Ctx->Resumed ? 1 : 0);
        printf("Rx-bytes: %llu\n", (unsigned long long)Ctx->RxBytes);
        printf("Tx-bytes: %llu\n", (unsigned long long)Ctx->TxBytes);
        printf("Ticket: %d\n", Ctx->TicketSaved ? 1 : 0);
        printf("Ticket-bytes: %u\n", Ctx->TicketBytes);
        printf("ZeroRTT-sent: %d\n", Ctx->SentEarly ? 1 : 0);

        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->ConnectionClose(Connection);
        }
        free(Ctx); // liberar memoria
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        if(VerboseEnabled){
            printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        }
        {
            /*
             * Campagne v3 : le ticket est ecrit (binaire) dans $TICKET_OUT pour etre relu par la connexion
             * SUIVANTE (chaque connexion est un processus distinct). Un seul ticket est conserve.
             * L'ancienne impression hexadecimale sur stdout est supprimee (elle polluait les journaux).
             */
            const char* TicketOut = getenv("TICKET_OUT");
            if (TicketOut != NULL && *TicketOut != '\0' && Ctx != NULL && !Ctx->TicketSaved) {
                FILE* Tf = fopen(TicketOut, "wb");
                if (Tf != NULL) {
                    size_t Wr = fwrite(Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, 1,
                                       Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength, Tf);
                    fclose(Tf);
                    if (Wr == Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength) {
                        Ctx->TicketSaved = TRUE;
                        Ctx->TicketBytes = Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
                    }
                }
            }
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

//
// Helper function to load a client configuration.
//
BOOLEAN
ClientLoadConfiguration(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the client's idle timeout. 
    //
    // Budget d'echec COMMUN TLS/QUIC (critere 4) : le `timeout` externe de
    // perftestClientTlsQuic.sh (HANDSHAKE_TIMEOUT_S, defaut 150 s) est
    // l'UNIQUE arbitre. Les timeouts internes MsQuic sont volontairement plus
    // larges (+30 s) pour ne JAMAIS declencher avant lui ; sinon QUIC
    // echouerait apres le HandshakeIdleTimeout par defaut (10 s) alors que TLS
    // continuerait jusqu'a 150 s -> politique d'echec non comparable.
    uint64_t BudgetMs = 150000;
    const char* BudgetEnv = getenv("HANDSHAKE_TIMEOUT_S");
    if (BudgetEnv != NULL && atoll(BudgetEnv) > 0) {
        BudgetMs = (uint64_t)atoll(BudgetEnv) * 1000;
    }
    uint64_t TransportMs = BudgetMs + 30000;
    Settings.IdleTimeoutMs = TransportMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    Settings.HandshakeIdleTimeoutMs = TransportMs;
    Settings.IsSet.HandshakeIdleTimeoutMs = TRUE;

    //
    // MTU de depart QUIC (facteur MTU du plan mecanistique), meme logique que le serveur : par defaut MsQuic
    // demarre a 1280 octets et ne sonde le MTU qu'apres le handshake. QUIC_MTU=<octets> (positionne par le
    // Launcher quand QUIC_MTU_SYNC=1) fixe MinimumMtu = MaximumMtu des DEUX extremites.
    //
    {
        const char* QuicMtuEnv = getenv("QUIC_MTU");
        if (QuicMtuEnv != NULL && *QuicMtuEnv != '\0') {
            unsigned long QuicMtu = strtoul(QuicMtuEnv, NULL, 10);
            if (QuicMtu >= 1280 && QuicMtu <= 1500) {
                Settings.MinimumMtu = (uint16_t)QuicMtu;
                Settings.IsSet.MinimumMtu = TRUE;
                Settings.MaximumMtu = (uint16_t)QuicMtu;
                Settings.IsSet.MaximumMtu = TRUE;
                fprintf(stderr, "QUIC MTU impose: %lu\n", QuicMtu);
            } else {
                fprintf(stderr, "QUIC_MTU invalide (%s) : ignore\n", QuicMtuEnv);
            }
        }
    }

    // 
    // Configures the server max TLS buffer to make account for the use of 
    // post-quamtum certificates and key exchange mechanisms.
    //
    Settings.TlsServerMaxSendBuffer = 0x100000; //0x8000;
    Settings.IsSet.TlsServerMaxSendBuffer = TRUE;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
    const char* CAfile;
    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (GetFlag(argc, argv, "unsecure")) {
        Config.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    } else if((CAfile = GetValue(argc, argv, "CAfile")) != NULL){
        Config.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
        Config.CredConfig.CaCertificateFile = (char*)CAfile;
    }

    const char* Cert;
    const char* KeyFile;
    if ((Cert = GetValue(argc, argv, "cert_file")) != NULL &&
               (KeyFile = GetValue(argc, argv, "key_file")) != NULL) {
        //
        // Loads the client's certificate from the file.
        //
        const char* Password = GetValue(argc, argv, "password");
        if (Password != NULL) {
            Config.CertFileProtected.CertificateFile = (char*)Cert;
            Config.CertFileProtected.PrivateKeyFile = (char*)KeyFile;
            Config.CertFileProtected.PrivateKeyPassword = (char*)Password;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            Config.CredConfig.CertificateFileProtected = &Config.CertFileProtected;
        } else {
            Config.CertFile.CertificateFile = (char*)Cert;
            Config.CertFile.PrivateKeyFile = (char*)KeyFile;
            Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            Config.CredConfig.CertificateFile = &Config.CertFile;
        }

    }
    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &Config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}


/*
 * ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
 * MODE CHARGE PERSISTANT (campagne v3, bras charge) -- active par LOAD_CONC=<c> (et LOAD_SECONDS, LOAD_TIMEOUT_S).
 *
 * POURQUOI : un processus `quics_connection` par connexion coute ~120 ms de CPU client (initialisation de MsQuic et d'oqsprovider),
 * 30 a 40 fois le CPU du serveur en ML-KEM : le generateur saturait avant le serveur (pilote du 27/10/2026). Ici UN processus,
 * UNE registration, UNE configuration, c fils ; chaque fil enchaine des connexions COMPLETES (handshake + requete/reponse de
 * 100 octets, memes definitions de mesure que ci-dessus) pendant LOAD_SECONDS secondes, sans temps de reflexion (boucle fermee).
 *
 * SORTIE (stdout, a la fin seulement ; le bruit des callbacks est redirige vers /dev/null pendant la mesure) :
 *   LOADCONN conc=<c> worker=<w> t_end=<epoch_ms> ok=<0|1> hs_ms=<..|NaN> app_ms=<..|NaN> rx=<octets|NA>
 * Format identique a celui de perftestLoadClient.sh / tls_load_client.c, lu par 13_analyse_extensions.py.
 * ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
 */
typedef struct {
    APP_CONNECTION_CTX Base;    /* DOIT rester le PREMIER membre : ClientSend / ClientStreamCallback recoivent &Base */
    sem_t Done;
} LOAD_CTX;

typedef struct { long long TEndMs; int Ok; double HsMs, AppMs; unsigned long long Rx; } LOAD_REC;
typedef struct { int Id; LOAD_REC* R; size_t N, Cap; } LOAD_WORKER;

static const char* g_LoadTarget;
static struct timespec g_LoadDeadline;   /* CLOCK_MONOTONIC */
static int g_LoadTimeoutS = 30;

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
LoadConnCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    LOAD_CTX* L = (LOAD_CTX*)Context;
    APP_CONNECTION_CTX* Ctx = &L->Base;
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED: {
        QUIC_STATISTICS Stats;
        uint32_t StatsLen = sizeof(Stats);
        memset(&Stats, 0, sizeof(Stats));
        if (QUIC_SUCCEEDED(MsQuic->GetParam(Connection, QUIC_PARAM_CONN_STATISTICS, &StatsLen, &Stats))) {
            double hs = (Stats.Timing.HandshakeFlightEnd - Stats.Timing.Start) / 1000.0;
            if (hs > 0 && hs < 1000000) {
                Ctx->HandshakeDurationMs = hs;
                Ctx->HandshakeMeasured = TRUE;
            }
            Ctx->RxBytes = Stats.Recv.TotalBytes;
            Ctx->TxBytes = Stats.Send.TotalBytes;
        }
        ClientSend(Connection, Ctx, QUIC_SEND_FLAG_NONE);
        break;
    }
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            MsQuic->ConnectionClose(Connection);
        }
        sem_post(&L->Done);          /* L reste la propriete du fil appelant (liberation apres sem_wait) */
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

static double LoadMsBetween(const struct timespec* A, const struct timespec* B)
{
    return (B->tv_sec - A->tv_sec) * 1000.0 + (B->tv_nsec - A->tv_nsec) / 1e6;
}

static void* LoadWorkerMain(void* Arg)
{
    LOAD_WORKER* W = (LOAD_WORKER*)Arg;
    for (;;) {
        struct timespec Now;
        clock_gettime(CLOCK_MONOTONIC, &Now);
        if (LoadMsBetween(&Now, &g_LoadDeadline) <= 0) break;

        LOAD_CTX* L = (LOAD_CTX*)calloc(1, sizeof(LOAD_CTX));
        if (L == NULL) break;
        sem_init(&L->Done, 0, 0);
        HQUIC Conn = NULL;
        int Ok = 0;
        if (QUIC_SUCCEEDED(MsQuic->ConnectionOpen(Registration, LoadConnCallback, L, &Conn))) {
            L->Base.Connection = Conn;
            clock_gettime(CLOCK_MONOTONIC, &L->Base.StartTime);
            if (QUIC_SUCCEEDED(MsQuic->ConnectionStart(Conn, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, g_LoadTarget, UdpPort))) {
                struct timespec Ts;
                clock_gettime(CLOCK_REALTIME, &Ts);
                Ts.tv_sec += g_LoadTimeoutS;
                if (sem_timedwait(&L->Done, &Ts) != 0) {
                    /* delai depasse : fermeture SILENCIEUSE (pas de paquet), puis attente de l'evenement de fin */
                    MsQuic->ConnectionShutdown(Conn, QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, 0);
                    while (sem_wait(&L->Done) != 0 && errno == EINTR) { }
                }
                Ok = (L->Base.AppReadyMeasured && L->Base.HandshakeMeasured) ? 1 : 0;
            } else {
                MsQuic->ConnectionClose(Conn);
            }
        }
        if (W->N == W->Cap) {
            W->Cap = W->Cap ? W->Cap * 2 : 4096;
            W->R = (LOAD_REC*)realloc(W->R, W->Cap * sizeof(LOAD_REC));
            if (W->R == NULL) { fprintf(stderr, "memoire insuffisante\n"); exit(2); }
        }
        {
            struct timespec Rt;
            clock_gettime(CLOCK_REALTIME, &Rt);
            LOAD_REC* R = &W->R[W->N++];
            R->TEndMs = (long long)Rt.tv_sec * 1000LL + Rt.tv_nsec / 1000000LL;
            R->Ok = Ok;
            R->HsMs = Ok ? L->Base.HandshakeDurationMs : 0;
            R->AppMs = Ok ? L->Base.AppReadyDurationMs : 0;
            R->Rx = L->Base.RxBytes;
        }
        sem_destroy(&L->Done);
        free(L);
    }
    return NULL;
}

static int RunLoad(const char* Target, int Conc, double Seconds)
{
    int i;
    const char* To = getenv("LOAD_TIMEOUT_S");
    if (To != NULL && atoi(To) > 0) g_LoadTimeoutS = atoi(To);
    g_LoadTarget = Target;

    /* stdout reel conserve pour le resultat ; le bruit des callbacks (printf non conditionnels) part vers /dev/null */
    fflush(stdout);
    int RealFd = dup(1);
    FILE* Out = (RealFd >= 0) ? fdopen(RealFd, "w") : stdout;
    if (freopen("/dev/null", "w", stdout) == NULL) { /* sans consequence */ }

    clock_gettime(CLOCK_MONOTONIC, &g_LoadDeadline);
    g_LoadDeadline.tv_sec += (time_t)Seconds;
    g_LoadDeadline.tv_nsec += (long)((Seconds - (double)(time_t)Seconds) * 1e9);
    if (g_LoadDeadline.tv_nsec >= 1000000000L) { g_LoadDeadline.tv_sec++; g_LoadDeadline.tv_nsec -= 1000000000L; }

    pthread_t* Th = (pthread_t*)calloc((size_t)Conc, sizeof(pthread_t));
    LOAD_WORKER* Ws = (LOAD_WORKER*)calloc((size_t)Conc, sizeof(LOAD_WORKER));
    for (i = 0; i < Conc; i++) { Ws[i].Id = i + 1; pthread_create(&Th[i], NULL, LoadWorkerMain, &Ws[i]); }
    for (i = 0; i < Conc; i++) pthread_join(Th[i], NULL);

    size_t Tot = 0, Bad = 0;
    for (i = 0; i < Conc; i++) {
        for (size_t j = 0; j < Ws[i].N; j++) {
            LOAD_REC* R = &Ws[i].R[j];
            Tot++;
            if (R->Ok) {
                fprintf(Out, "LOADCONN conc=%d worker=%d t_end=%lld ok=1 hs_ms=%.3f app_ms=%.3f rx=%llu\n",
                        Conc, Ws[i].Id, R->TEndMs, R->HsMs, R->AppMs, R->Rx);
            } else {
                Bad++;
                fprintf(Out, "LOADCONN conc=%d worker=%d t_end=%lld ok=0 hs_ms=NaN app_ms=NaN rx=NA\n", Conc, Ws[i].Id, R->TEndMs);
            }
        }
    }
    fflush(Out);
    fprintf(stderr, "quics_connection (charge): conc=%d connexions=%zu echecs=%zu\n", Conc, Tot, Bad);
    return 0;
}

int
QUIC_MAIN_EXPORT
main(
    _In_ int argc,
    _In_reads_(argc) _Null_terminated_ char* argv[]
    )
{

    const char* Groups = NULL;
    if((Groups = GetValue(argc, argv, "groups")) != NULL) {
        setenv(GroupsListVar, Groups, 1);
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    //gettimeofday(&Stop, NULL);
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (GetFlag(argc, argv, "help") || GetFlag(argc, argv, "?")) {
        PrintUsage();
    } 
    else {
        //
        // Load the client configuration based on the "unsecure" command line option.
        //
        if (!ClientLoadConfiguration(argc, argv)) {
            goto Error;
        }

        QUIC_STATUS Status;
        const char* SslKeyLogFile = getenv(SslKeyLogEnvVar);

        HQUIC Connection = NULL;

        const char* Target;
        if ((Target = GetValue(argc, argv, "target")) == NULL) {
            printf("Must specify '-target' argument!\n");
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }

        if(GetFlag(argc, argv, "verbose")) {
            VerboseEnabled = TRUE;
        }

        {   /* campagne v3 : mode charge persistant (LOAD_CONC=<c>, LOAD_SECONDS=<s>) */
            const char* LoadConc = getenv("LOAD_CONC");
            if (LoadConc != NULL && atoi(LoadConc) > 0) {
                const char* LoadSec = getenv("LOAD_SECONDS");
                Status = (QUIC_STATUS)RunLoad(Target, atoi(LoadConc), (LoadSec != NULL && atof(LoadSec) > 0) ? atof(LoadSec) : 20.0);
                goto Error;
            }
        }

        //
        // Allocate a new connection object.
        //
        if (QUIC_FAILED(Status = MsQuic->ConnectionOpen(Registration, ClientConnectionCallback, NULL, &Connection))) {
            printf("ConnectionOpen failed, 0x%x!\n", Status);
            if (Connection != NULL) {
                MsQuic->ConnectionClose(Connection);
            }
        }

        // Asociar contexto
        APP_CONNECTION_CTX* Ctx = (APP_CONNECTION_CTX*)calloc(1, sizeof(APP_CONNECTION_CTX));
        Ctx->Connection = Connection;
        MsQuic->SetContext(Connection, Ctx);

        /*
         * Campagne v3 -- REPRISE DE SESSION : si $TICKET_IN designe un fichier non vide, le ticket est
         * fourni a MsQuic AVANT ConnectionStart (QUIC_PARAM_CONN_RESUMPTION_TICKET). La lecture du fichier
         * a lieu AVANT la capture de StartTime : elle n'entre pas dans la duree mesuree.
         * ZERORTT=1 : la requete applicative est en plus envoyee en 0-RTT (apres ConnectionStart).
         */
        BOOLEAN HaveTicket = FALSE;
        {
            const char* TicketIn = getenv("TICKET_IN");
            if (TicketIn != NULL && *TicketIn != '\0') {
                FILE* Tf = fopen(TicketIn, "rb");
                if (Tf != NULL) {
                    uint8_t* Tb = (uint8_t*)malloc(16384);
                    size_t Tl = (Tb != NULL) ? fread(Tb, 1, 16384, Tf) : 0;
                    fclose(Tf);
                    if (Tl > 0) {
                        QUIC_STATUS St2 = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_RESUMPTION_TICKET, (uint32_t)Tl, Tb);
                        if (QUIC_SUCCEEDED(St2)) {
                            HaveTicket = TRUE;
                        } else {
                            printf("SetParam(QUIC_PARAM_CONN_RESUMPTION_TICKET) failed, 0x%x!\n", St2);
                        }
                    }
                    free(Tb);
                }
                printf("Ticket-in: %s\n", HaveTicket ? "loaded" : "missing");
            }
        }
        const char* ZeroRttEnv = getenv("ZERORTT");
        BOOLEAN WantZeroRtt = (ZeroRttEnv != NULL && *ZeroRttEnv == '1');
            
        //
        // Start the connection to the server.
        //

        if (SslKeyLogFile != NULL) {
            if (QUIC_FAILED(Status = MsQuic->SetParam(Connection, QUIC_PARAM_CONN_TLS_SECRETS, sizeof(ClientSecrets), &ClientSecrets))) {
                printf("SetParam(QUIC_PARAM_CONN_TLS_SECRETS) failed, 0x%x!\n", Status);
            }
        }

        //
        // Point 4 du prescreen TDSC (TDSC-2026-09-3862) : borne de depart
        // pour "App-ready duration", symetrique du starttime capture juste
        // avant SSL_connect() cote TLS (apps/s_connection.c).
        //
        clock_gettime(CLOCK_MONOTONIC, &Ctx->StartTime);

        if (QUIC_FAILED(Status = MsQuic->ConnectionStart(Connection, Configuration, QUIC_ADDRESS_FAMILY_UNSPEC, Target, UdpPort))) {
            printf("ConnectionStart failed, 0x%x!\n", Status);
            if (Connection != NULL) {
                MsQuic->ConnectionClose(Connection);
            }
        } else if (WantZeroRtt && HaveTicket) {
            /* 0-RTT : requete envoyee avant la fin du handshake (cle 0-RTT issue du ticket). */
            Ctx->SentEarly = TRUE;
            ClientSend(Connection, Ctx, QUIC_SEND_FLAG_ALLOW_0_RTT);
        }
    }

Error:

    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}
