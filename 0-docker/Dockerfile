ARG LIBOQS_TAG=0.12.0
ARG MSQUIC_TAG=6b7302f8676f9d0e88ad0883bf3980fe5166c4b7
ARG OQSPROVIDER_TAG=0.8.0
ARG OPENSSL_TAG=e7ac728c4aa09f5f234363834a9f8bbac525d99d
ARG MAKE_DEFINES="-j 4"      
ARG MSQUIC_DEBUG=off        
ARG LIBOQS_BUILD_DEFINES="-DOQS_DIST_BUILD=ON"
ARG BASEDIR=/opt
ARG INSTALLDIR=${BASEDIR}/oqssa
ARG LIBOQSDIR=${BASEDIR}/liboqs
ARG MSQUICDIR=${BASEDIR}/msquic-pq
ARG OPENSSLDIR=${BASEDIR}/openssl
ARG OQSPROVIDERDIR=${BASEDIR}/oqs-provider
ARG LIBDIR

# --------------------------------------
# Stage 1: Install all necessary tools
# --------------------------------------
FROM ubuntu:24.10 AS base
ENV DEBIAN_FRONTEND=noninteractive

# Configuration des dépôts vers old-releases & installation des dépendances
RUN set -eux; \
  if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
    sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources; \
    sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources; \
  fi; \
  if [ -f /etc/apt/sources.list ]; then \
    sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list; \
    sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list; \
  fi; \
  apt-get update; \
  apt-get install -y --no-install-recommends \
    cmake gcc ninja-build libunwind-dev \
    pkg-config build-essential \
    cargo git wget ca-certificates \
    openssl libssl-dev; \
  rm -rf /var/lib/apt/lists/*

# --------------------------------------
# Stage 2: Download all necessary sources
# --------------------------------------
FROM base AS download
ARG BASEDIR
ARG LIBOQS_TAG
ARG MSQUIC_TAG
ARG OPENSSL_TAG
ARG OQSPROVIDER_TAG
ARG OPENSSLDIR
ARG LIBOQSDIR
ARG MSQUICDIR
ARG OQSPROVIDERDIR

WORKDIR $BASEDIR

# Config git globale optimisée : désactivation compression HTTP, augmentation du buffer à 2 Go,
# timeout allongé et passage forcé en HTTP/1.1 pour empêcher les ruptures de stream (curl 18 / 92)
RUN git config --global http.version HTTP/1.1 && \
    git config --global http.postBuffer 2147483648 && \
    git config --global core.compression 0 && \
    git config --global net.cURLTimeOut 600 && \
    git config --global http.lowSpeedLimit 0 && \
    git config --global http.lowSpeedTime 999999

# Download liboqs avec tentative multiple
RUN if [ ! -d "${LIBOQSDIR}" ]; then \
        mkdir -p liboqs && \
        for i in 1 2 3 4 5; do git clone --recursive --depth 1 --branch ${LIBOQS_TAG} https://github.com/open-quantum-safe/liboqs.git ${LIBOQSDIR} && break || sleep 5; done; \
    fi

# Download msquic-pq avec tentative multiple et isolation unitaire des submodules
RUN if [ ! -d "${MSQUICDIR}" ]; then \
        mkdir -p "${MSQUICDIR}" && cd "${MSQUICDIR}" && \
        git init -q && \
        git remote add origin https://github.com/montenegro-montes/msquic-pq.git && \
        (for i in 1 2 3 4 5; do git fetch --depth 1 origin ${MSQUIC_TAG} && break || sleep 5; done) && \
        git checkout -q FETCH_HEAD && \
        for sub in submodules/clog submodules/googletest submodules/liboqs submodules/oqsprovider submodules/openssl submodules/openssl3; do \
            for i in 1 2 3 4 5; do \
                git submodule update --init --depth 1 -- "$sub" && break || sleep 5; \
            done; \
        done; \
        for sub in submodules/clog submodules/googletest submodules/liboqs submodules/oqsprovider; do \
            for i in 1 2 3 4 5; do \
                git submodule update --init --recursive --depth 1 -- "$sub" && break || sleep 5; \
            done; \
        done; \
    fi

# Point 4 du prescreen TDSC (TDSC-2026-09-3862) : injection des patchs
# "App-ready duration" par-dessus le clone pinne de msquic-pq.
COPY patches/s_connection_quic.c ${MSQUICDIR}/src/tools/s_connection/s_connection.c
COPY patches/s_server_quic.c ${MSQUICDIR}/src/tools/s_server/s_server.c

# Critique 2/4 (AE) : UDP GSO desactive par defaut dans MsQuic (un super-paquet GSO = 1 seul
# tirage de perte netem pour plusieurs datagrammes, contrairement a TCP avec TSO coupe).
# Le script ECHOUE (donc le build) si le patch ne s'applique pas exactement une fois.
COPY patches/apply_no_udp_gso.sh /tmp/apply_no_udp_gso.sh
RUN sh /tmp/apply_no_udp_gso.sh ${MSQUICDIR}/src/platform/datapath_epoll.c && rm -f /tmp/apply_no_udp_gso.sh

# Download openssl avec tentative multiple
RUN if [ ! -d "${OPENSSLDIR}" ]; then \
        mkdir -p "${OPENSSLDIR}" && cd "${OPENSSLDIR}" && \
        git init -q && \
        git remote add origin https://github.com/montenegro-montes/openssl.git && \
        (for i in 1 2 3 4 5; do git fetch --depth 1 origin ${OPENSSL_TAG} && break || sleep 5; done) && \
        git checkout -q FETCH_HEAD ; \
    fi

# Point 4 du prescreen TDSC (TDSC-2026-09-3862) : injection du patch
# "App-ready duration" par-dessus le clone pinne (evite de forker/pousser
# une branche a chaque iteration -- cf. discussion avec Claude 27/09/2026).
COPY patches/s_connection_tls.c ${OPENSSLDIR}/apps/s_connection.c

# Modification des limites dans speed.c
WORKDIR ${OPENSSLDIR}
RUN sed -i 's/#define MAX_SIG_NUM .*/#define MAX_SIG_NUM 512/' ./apps/speed.c && \
    sed -i 's/#define MAX_KEM_NUM .*/#define MAX_KEM_NUM 512/' ./apps/speed.c

WORKDIR $BASEDIR    
RUN if [ ! -d "${OQSPROVIDERDIR}" ]; then \
        mkdir -p oqs-provider && \
        for i in 1 2 3 4 5; do git clone --depth 1 --branch ${OQSPROVIDER_TAG} https://github.com/open-quantum-safe/oqs-provider.git ${OQSPROVIDERDIR} && break || sleep 5; done; \
    fi

# --------------------------------------
# Stage 3: Build the tools
# --------------------------------------
FROM download AS build
ARG MAKE_DEFINES     
ARG MSQUIC_DEBUG
ARG LIBOQS_BUILD_DEFINES
ARG INSTALLDIR
ARG LIBOQSDIR
ARG MSQUICDIR
ARG OPENSSLDIR
ARG OQSPROVIDERDIR
ARG LIBDIR

# Build and install liboqs
WORKDIR ${LIBOQSDIR}/build
RUN cmake -G"Ninja" .. ${LIBOQS_BUILD_DEFINES} && \
    ninja -j"$(nproc)" && \
    ninja install

FROM build AS build_1
ARG MAKE_DEFINES     
ARG MSQUIC_DEBUG
ARG LIBOQS_BUILD_DEFINES
ARG INSTALLDIR
ARG LIBOQSDIR
ARG MSQUICDIR
ARG OPENSSLDIR
ARG OQSPROVIDERDIR
ARG LIBDIR

# Install required build tools and system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends python3 golang-go python3-pip && \ 
    pip install jinja2 tabulate pyyaml --break-system-packages 

# Installation des bibliothèques de compression
RUN apt-get update && apt-get install -y --no-install-recommends \
    zlib1g-dev \
    libbrotli-dev \
    libzstd-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Build and install MsQuic
WORKDIR ${MSQUICDIR}
RUN mkdir -p build && cd build && \ 
    cmake -G 'Unix Makefiles' -DQUIC_ENABLE_LOGGING=${MSQUIC_DEBUG} -DQUIC_LOGGING_TYPE=stdout \ 
    -DQUIC_ENABLE_OQS_PROVIDER=on -DQUIC_TLS=openssl3 -DQUIC_BUILD_TOOLS=on .. && \ 
    cmake -G 'Unix Makefiles' -DQUIC_ENABLE_LOGGING=${MSQUIC_DEBUG} -DQUIC_LOGGING_TYPE=stdout \ 
    -DQUIC_ENABLE_OQS_PROVIDER=on -DQUIC_TLS=openssl3 -DQUIC_BUILD_TOOLS=on .. && \
    cmake --build .

# Build OpenSSL3 avec support compression
WORKDIR ${OPENSSLDIR}
RUN LIBDIR=$(uname -m | grep -q x86_64 && echo "lib64" || echo "lib") && \ 
    LDFLAGS="-Wl,-rpath -Wl,${INSTALLDIR}/${LIBDIR}" ./config shared \
        --prefix=${INSTALLDIR} \
        enable-tls1_3 \
        enable-ec \
        enable-ec_nistp_64_gcc_128 \
        enable-zlib \
        enable-brotli \
        enable-zstd \
        no-deprecated \
        -Wl,-rpath,${INSTALLDIR}/${LIBDIR} && \
    make ${MAKE_DEFINES} && make install_sw install_ssldirs

# --------------------------------------
# Stage 4: Configure the tools
# --------------------------------------
FROM build_1 AS configure
ARG INSTALLDIR
ARG OQSPROVIDERDIR
ARG LIBOQSDIR
ARG OQSPROVIDER_TAG

ENV PATH="${INSTALLDIR}/bin:${PATH}"

# Garde-fou : la boucle de clonage de l'etage "download" (for ... && break || sleep) retourne 0 meme quand les
# 5 tentatives echouent (reseau/DNS intermittent) : le build continue alors avec un dossier oqs-provider VIDE et
# n'echoue qu'ici ("oqs-template/generate.yml: No such file"). On reclone donc ICI si le dossier est vide, et on
# echoue explicitement si le clonage est impossible. (Place dans l'etage configure pour ne pas invalider les
# couches de compilation de liboqs/OpenSSL/MsQuic deja en cache.)
RUN if [ ! -f "${OQSPROVIDERDIR}/oqs-template/generate.yml" ]; then \
        echo ">>> oqs-provider absent ou vide : nouveau clonage (${OQSPROVIDER_TAG})"; \
        rm -rf "${OQSPROVIDERDIR}"; \
        for i in 1 2 3 4 5 6; do \
            git clone --depth 1 --branch "${OQSPROVIDER_TAG}" https://github.com/open-quantum-safe/oqs-provider.git "${OQSPROVIDERDIR}" && break; \
            echo "   clonage oqs-provider: tentative $i echouee"; rm -rf "${OQSPROVIDERDIR}"; sleep 10; \
        done; \
    fi && \
    test -f "${OQSPROVIDERDIR}/oqs-template/generate.yml" || { echo "ERREUR: oqs-provider introuvable (reseau ?)"; exit 1; }

# Configure oqs-provider to activate all algorithms
WORKDIR ${OQSPROVIDERDIR}
RUN sed -i "s/false/true/g" oqs-template/generate.yml && \ 
    LIBOQS_SRC_DIR=${LIBOQSDIR} python3 oqs-template/generate.py

# Build OQS provider
WORKDIR ${OQSPROVIDERDIR}
RUN ln -s ../openssl . && \
    cmake -DOPENSSL_ROOT_DIR=${INSTALLDIR} -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=${INSTALLDIR} -S . -B _build && \
    cmake --build _build 

RUN LIBDIR=$(uname -m | grep -q x86_64 && echo "lib64" || echo "lib") && \ 
    cp _build/lib/oqsprovider.so ${INSTALLDIR}/${LIBDIR}/ossl-modules/

# Modify the openssl configuration file
RUN sed -i "s/default = default_sect/default = default_sect\noqsprovider = oqsprovider_sect/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/\[default_sect\]/\[default_sect\]\nactivate = 1\n\[oqsprovider_sect\]\nactivate = 1\n/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/providers = provider_sect/providers = provider_sect\nssl_conf = ssl_sect\n\n\[ssl_sect\]\nsystem_default = system_default_sect\n\n\[system_default_sect\]\nGroups = \$ENV\:\:DEFAULT_GROUPS\n/g" ${INSTALLDIR}/ssl/openssl.cnf && \ 
    sed -i "s/\# Use this in order to automatically load providers/\# Set default KEM groups if not set via environment variable\nKDEFAULT_GROUPS = $DEFAULT_GROUPS\n\n# Use this in order to automatically load providers/g" ${INSTALLDIR}/ssl/openssl.cnf && \
    sed -i "s/HOME\t\t\t= ./HOME\t\t= .\nDEFAULT_GROUPS\t= ${DEFAULT_GROUPS}/g" ${INSTALLDIR}/ssl/openssl.cnf

# --------------------------------------
# Stage 5: Runtime
# --------------------------------------
FROM ubuntu:24.10 AS runtime
ARG INSTALLDIR
ARG MSQUICDIR
ARG OQSPROVIDERDIR

ENV PATH="${INSTALLDIR}/bin:${PATH}"
ENV OPENSSL=${INSTALLDIR}/bin/openssl
ENV OPENSSL_CNF=${INSTALLDIR}/ssl/openssl.cnf

RUN set -eux; \
  if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then \
    sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources; \
    sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources; \
  fi; \
  if [ -f /etc/apt/sources.list ]; then \
    sed -i 's|http://archive.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list; \
    sed -i 's|http://security.ubuntu.com/ubuntu|http://old-releases.ubuntu.com/ubuntu|g' /etc/apt/sources.list; \
  fi; \
  apt-get update; \
  apt-get install -y --no-install-recommends \
    ca-certificates iproute2 tcpdump net-tools ethtool \
    zlib1g \
    libbrotli1 \
    libzstd1 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=configure ${INSTALLDIR} ${INSTALLDIR}
COPY --from=configure ${MSQUICDIR}/build/bin/Release/ ${INSTALLDIR}/bin/
COPY --from=configure ${OQSPROVIDERDIR}/_build/lib/oqsprovider.so /tmp

RUN cp $INSTALLDIR/ssl/openssl.cnf $(openssl version -m | cut -d '"' -f2) && \
    LIBDIR=$(uname -m | grep -q x86_64 && echo "lib64" || echo "lib") && \ 
    cp ${INSTALLDIR}/${LIBDIR}/ossl-modules/* $(openssl version -d | cut -d '"' -f2)

COPY scripts/*.sh ${INSTALLDIR}/bin/
RUN chmod 755 ${INSTALLDIR}/bin/*.sh

# Point 4 du prescreen TDSC (TDSC-2026-09-3862) : charge utile fixe de 100
# octets, servie par "openssl s_server -WWW" (perftestServerTlsQuic.sh) et
# demandee par "openssl s_connection -www /payload.bin"
# (perftestClientTlsQuic.sh). Meme taille que SendBufferLength cote QUIC
# (s_connection_quic.c / s_server_quic.c), pour une comparaison symetrique.
COPY patches/payload.bin ${INSTALLDIR}/bin/payload.bin

WORKDIR ${INSTALLDIR}/bin

CMD ["/bin/bash"]
