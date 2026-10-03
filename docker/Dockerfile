# DFIR toolkit image (tri-OS)
# Container-only forensic analysis: Windows (EVTX, MFT, registry, execution
# artifacts), Linux (journals, auditd, disk images), macOS (plists, unified
# logs, SQLite), and network (PCAP/PCAPNG).
#
# Build:  docker build -t dfir-toolkit docker/
#
# Pinned-component versions are declared below for reproducibility.

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# ---- component versions -----------------------------------------------------
ENV EVTX_DUMP_VER=v0.12.3 \
    CHAINSAW_VER=v2.16.5 \
    HAYABUSA_VER=4.1.0 \
    SIGMA_REF=r2026-07-01 \
    DOTNET_CHANNEL=9.0

# ---- base OS packages -------------------------------------------------------
# Includes cross-platform parsers, SQLite/EDB readers, archive/disk-image
# tools, and the build deps required to install plaso from source.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg xz-utils unzip zip tar git \
        python3 python3-pip python3-dev \
        build-essential pkg-config \
        libssl-dev liblzma-dev zlib1g-dev libffi-dev \
        tshark tcpdump tcpflow \
        sleuthkit \
        sqlite3 \
        p7zip-full \
        libesedb-utils \
        yara \
        foremost \
        ewf-tools \
        libfsapfs-utils \
        libfvde-utils \
        libvmdk-utils \
        libvslvm-utils \
        libbde-utils \
        vmfs-tools vmfs6-tools qemu-utils \
        util-linux \
        clamav \
        jq ripgrep file less vim-tiny \
        binutils \
        libicu74 \
        brotli \
    && rm -rf /var/lib/apt/lists/*

# Non-interactive tshark (no privilege issue in container)
RUN echo 'wireshark-common wireshark-common/install-setuid boolean false' \
        | debconf-set-selections || true

# ---- .NET runtime (for Eric Zimmerman tools) --------------------------------
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
    && bash /tmp/dotnet-install.sh --channel "${DOTNET_CHANNEL}" --runtime dotnet --install-dir /usr/share/dotnet \
    && ln -s /usr/share/dotnet/dotnet /usr/local/bin/dotnet \
    && rm /tmp/dotnet-install.sh

# ---- evtx_dump (Rust, static musl) ------------------------------------------
# NOTE: named evtx_dump_rs to avoid colliding with python-evtx's evtx_dump.
RUN curl -fsSL -o /usr/local/bin/evtx_dump_rs \
        "https://github.com/omerbenamram/evtx/releases/download/${EVTX_DUMP_VER}/evtx_dump-${EVTX_DUMP_VER}-x86_64-unknown-linux-musl" \
    && chmod +x /usr/local/bin/evtx_dump_rs

# ---- Chainsaw (Sigma hunting / EVTX triage) ---------------------------------
RUN curl -fsSL -o /tmp/chainsaw.tar.gz \
        "https://github.com/WithSecureOpenSource/chainsaw/releases/download/${CHAINSAW_VER}/chainsaw_x86_64-unknown-linux-gnu.tar.gz" \
    && mkdir -p /opt/chainsaw \
    && tar -xzf /tmp/chainsaw.tar.gz -C /opt/chainsaw --strip-components=1 \
    && ln -s /opt/chainsaw/chainsaw /usr/local/bin/chainsaw \
    && rm /tmp/chainsaw.tar.gz

# ---- Hayabusa (Windows EVTX fast-forensics timeline) ------------------------
RUN curl -fsSL -o /tmp/hayabusa.zip \
        "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VER}/hayabusa-${HAYABUSA_VER}-lin-x64-gnu.zip" \
    && mkdir -p /opt/hayabusa \
    && unzip -q /tmp/hayabusa.zip -d /opt/hayabusa \
    && chmod +x "/opt/hayabusa/hayabusa-${HAYABUSA_VER}-lin-x64-gnu" \
    && ln -s "/opt/hayabusa/hayabusa-${HAYABUSA_VER}-lin-x64-gnu" /usr/local/bin/hayabusa \
    && rm /tmp/hayabusa.zip

# ---- Sigma rules (for Chainsaw) ---------------------------------------------
RUN git clone --depth 1 --branch "${SIGMA_REF}" https://github.com/SigmaHQ/sigma.git /opt/sigma \
    && rm -rf /opt/sigma/.git

# ---- Eric Zimmerman tools (.NET 9) ------------------------------------------
# Each tool ships as net9/<Tool>.zip containing <Tool>.dll. Fetch, unpack, and
# wrap in a small launcher on PATH.
RUN set -eux; \
    for tool in MFTECmd PECmd LECmd JLECmd SBECmd AmcacheParser \
                AppCompatCacheParser SrumECmd RECmd EvtxECmd; do \
        curl -fsSL -o "/tmp/${tool}.zip" "https://download.ericzimmermanstools.com/net9/${tool}.zip"; \
        mkdir -p "/opt/zimmerman/${tool}"; \
        unzip -q "/tmp/${tool}.zip" -d "/opt/zimmerman/${tool}"; \
        printf '#!/bin/sh\nexec dotnet /opt/zimmerman/%s/%s.dll "$@"\n' "${tool}" "${tool}" \
            > "/usr/local/bin/${tool}"; \
        chmod +x "/usr/local/bin/${tool}"; \
        rm -f "/tmp/${tool}.zip"; \
    done

# ---- Python DFIR libraries --------------------------------------------------
# python-evtx        - EVTX parsing fallback
# regipy/python-registry - Windows registry hives
# plaso              - cross-platform super-timeline (log2timeline.py/psort.py)
# volatility3        - memory forensics
# yara-python        - pattern matching
# dfir-unfurl        - browser/URL history
RUN pip3 install --no-cache-dir --break-system-packages \
        python-evtx \
        pandas \
        python-dateutil \
        regipy \
        python-registry \
        volatility3 \
        yara-python \
        dfir-unfurl

# ---- plaso (super-timeline engine; large install, kept as its own layer) ----
# Plaso installs console scripts without the .py suffix; add the conventional
# aliases so `log2timeline.py`/`psort.py` (as used in docs) also work.
RUN pip3 install --no-cache-dir --break-system-packages plaso \
    && ln -sf /usr/local/bin/log2timeline /usr/local/bin/log2timeline.py \
    && ln -sf /usr/local/bin/psort /usr/local/bin/psort.py \
    && ln -sf /usr/local/bin/pinfo /usr/local/bin/pinfo.py

# ---- Zeek (network logs: mssql, smb, dce_rpc, kerberos, http) ---------------
RUN . /etc/os-release \
    && echo "deb [trusted=yes] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${VERSION_ID}/ /" \
        > /etc/apt/sources.list.d/zeek.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends zeek-lts \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek \
    && ln -sf /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut || true

# ---- YARA rule sets (signature-base + Yara-Rules) ---------------------------
# Used by `yara`, `yara-python`, and docker/av_triage.py. Individual rule files
# are compiled by the helper; invalid/unsupported rules are skipped gracefully.
RUN git clone --depth 1 https://github.com/Neo23x0/signature-base.git \
        /opt/yara-rules/signature-base \
    && git clone --depth 1 https://github.com/Yara-Rules/rules.git \
        /opt/yara-rules/yara-rules \
    && rm -rf /opt/yara-rules/*/.git

# ---- ClamAV signature database ----------------------------------------------
# `clamscan` from the base layer has no signatures. Fetch the CVD database at
# build time so the image is usable offline; refresh later with `freshclam`.
# The clamd/clamav-daemon layer is not installed (only the CLI scanner is used).
RUN freshclam --quiet || true \
    && rm -rf /var/lib/clamav/*.sign \
    && ls -la /var/lib/clamav

# ---- mac_apt (macOS plists, unified logs, FSEvents, SQLite artifacts) -------
# mac_apt runs from source (no setup.py). Notes:
#  * pyaff4 depends on the broken `fastchunking` sdist; install pybindgen first
#    so its C++ binding generates, then build fastchunking without isolation.
#  * mac_apt pins pytsk3==20230125, which fails to link libbfio and conflicts
#    with plaso (needs >=20260715). Reinstall newer pytsk3 last so both work.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libtsk-dev libbfio-dev \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/ydkhatri/mac_apt.git /opt/mac_apt \
    && rm -rf /opt/mac_apt/.git \
    && pip3 install --no-cache-dir --break-system-packages pybindgen==0.21.0 \
    && pip3 install --no-cache-dir --break-system-packages --no-build-isolation \
        "fastchunking==0.0.3" \
    && cd /opt/mac_apt \
    && pip3 install --no-cache-dir --break-system-packages -r requirements.txt \
    && pip3 install --no-cache-dir --break-system-packages --force-reinstall \
        "pytsk3>=20260715" \
    && printf '#!/bin/sh\nexec python3 /opt/mac_apt/mac_apt.py "$@"\n' \
        > /usr/local/bin/mac_apt && chmod +x /usr/local/bin/mac_apt

# ---- Visualization assets (incident_viz.py) ---------------------------------
# Static-format deps and vendored JS. Kept in a late layer so adding them does
# not invalidate the heavy plaso/Zeek/ClamAV/mac_apt layers above.
RUN pip3 install --no-cache-dir --break-system-packages matplotlib networkx

# Vendor the JS bundles so rendered HTML is single-file and fully offline.
# The helper inlines these into each deliverable (no network, no CDN).
ENV VIS_NETWORK_VER=9.1.9 \
    VIS_TIMELINE_VER=7.7.3
RUN mkdir -p /opt/viz-assets \
    && curl -fsSL -o /opt/viz-assets/vis-network.min.js \
        "https://unpkg.com/vis-network@${VIS_NETWORK_VER}/standalone/umd/vis-network.min.js" \
    && curl -fsSL -o /opt/viz-assets/vis-timeline-graph2d.min.js \
        "https://unpkg.com/vis-timeline@${VIS_TIMELINE_VER}/standalone/umd/vis-timeline-graph2d.min.js" \
    && curl -fsSL -o /opt/viz-assets/vis-timeline-graph2d.min.css \
        "https://unpkg.com/vis-timeline@${VIS_TIMELINE_VER}/styles/vis-timeline-graph2d.min.css"

# ---- analysis helper: incident visualization --------------------------------
RUN printf '#!/bin/sh\nexec python3 /data/tools/incident_viz.py "$@"\n' \
        > /usr/local/bin/incident_viz && chmod +x /usr/local/bin/incident_viz

# ---- ForensicArtifacts catalog (coverage manifest, not a parser) ------------
# YAML definitions of artifact locations for Windows/Linux/macOS. Used as a
# checklist to compare present evidence against known artifact classes.
RUN git clone --depth 1 https://github.com/ForensicArtifacts/artifacts.git /opt/forensic-artifacts \
    && rm -rf /opt/forensic-artifacts/.git

# ---- analysis helper: dump one EVTX to JSONL with evtx_dump ------------------
RUN printf '#!/bin/sh\n# usage: evtx2json <file.evtx> [out.jsonl]\nexec evtx_dump_rs -o jsonl "$@"\n' \
        > /usr/local/bin/evtx2json && chmod +x /usr/local/bin/evtx2json

# ---- ESXi triage helper -----------------------------------------------------
# Parse/hunt VMware ESXi support bundles. The script itself is mounted from
# docker/ at /data/tools/; this creates a PATH entry for convenience.
RUN printf '#!/bin/sh\nexec python3 /data/tools/esxi_triage.py "$@"\n' \
        > /usr/local/bin/esxi_triage && chmod +x /usr/local/bin/esxi_triage

# Output ownership: run as the caller's uid/gid (see docker/dfir.sh)
WORKDIR /data
CMD ["/bin/bash"]
