# Current Python security release. The manifest digest covers supported architectures.
FROM docker.io/library/python:3.12.16-alpine3.24@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8 AS native
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 TZ=UTC
ENV CFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3" \
    CXXFLAGS="-O2 -fstack-protector-strong -D_FORTIFY_SOURCE=3" \
    LDFLAGS="-Wl,-z,relro,-z,now"
RUN apk update && apk upgrade --no-cache && apk add --no-cache \
    build-base cmake ninja cargo rust bison flex perl pkgconf zlib-dev xz-dev \
    openssl-dev curl-dev bzip2-dev json-c-dev libmspack-dev pcre2-dev linux-headers \
    musl-fts-dev ncurses-dev check-dev leptonica-dev icu-dev lz4-dev zstd-dev \
    readline-dev libseccomp-dev libffi-dev freetype-dev lcms2-dev openjpeg-dev \
    libwebp-dev tiff-dev libavif-dev libraqm-dev py3-pytest gtest-dev gmock
COPY deploy/native/sources.lock.json /build-tools/sources.lock.json
COPY scripts/fetch_native.py scripts/patch_clamav_rand.py scripts/patch_clamav_onenote.py scripts/patch_clamav_loopback.py scripts/build_native.sh deploy/native/onenote_path_policy.rs /build-tools/
RUN python /build-tools/fetch_native.py /build-tools/sources.lock.json /sources
RUN sh /build-tools/build_native.sh libxml2
RUN sh /build-tools/build_native.sh postgresql18
RUN sh /build-tools/build_native.sh tesseract-ocr
RUN sh /build-tools/build_native.sh clamav
# Retain Alpine's full BusyBox configuration and applets; backport URL validation.
COPY deploy/native/busybox.lock.json /build-tools/busybox.lock.json
COPY scripts/build_busybox.sh scripts/patch_busybox_wget.py scripts/check_busybox_wget.py /build-tools/
RUN apk add --no-cache utmps-dev utmps-static \
    && python /build-tools/fetch_native.py /build-tools/busybox.lock.json /sources/busybox \
    && sh /build-tools/build_busybox.sh

FROM native AS python-build
ENV PATH="/usr/lib/postgresql/18/bin:${PATH}"
WORKDIR /app
COPY requirements.lock requirements-inspection.lock pyproject.toml README.md LICENSE NOTICE ./
# Use patched shared OpenSSL, libpq and TIFF; do not import bundled wheel copies.
RUN pip wheel --no-deps --wheel-dir=/wheels /sources/cryptography-50.0.1.tar.gz \
    /sources/pillow-13.0.0.tar.gz /sources/psycopg_c-3.3.6.tar.gz \
    && python -c 'from pathlib import Path; names=("cryptography==", "pillow==", "psycopg-c=="); Path("/tmp/other.lock").write_text("\n".join(sorted({line for path in ("requirements.lock", "requirements-inspection.lock") for line in Path(path).read_text().splitlines() if not line.startswith(names)})) + "\n")' \
    && pip wheel --no-deps --wheel-dir=/wheels -r /tmp/other.lock
COPY mailsec ./mailsec
RUN pip wheel --no-deps --wheel-dir=/wheels .

FROM docker.io/library/python:3.12.16-alpine3.24@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8
ARG VCS_REF=unpublished
LABEL org.opencontainers.image.title="Mailsec" \
    org.opencontainers.image.authors="Derrik Trace" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.version="0.4.0-alpha.8" \
    org.opencontainers.image.source="https://github.com/derriktrace/mailsec" \
    org.opencontainers.image.revision="${VCS_REF}" \
    org.opencontainers.image.description="Self-hosted Gmail monitoring with evidence review and local attachment inspection"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PIP_NO_CACHE_DIR=1 TZ=UTC
WORKDIR /app
RUN apk update && apk upgrade --no-cache && apk add --no-cache \
    libseccomp poppler-utils leptonica icu-libs lz4-libs zstd-libs readline \
    openssl libcurl libbz2 json-c libmspack pcre2 ncurses-libs libgcc libstdc++ \
    libffi freetype lcms2 openjpeg libwebp libwebpdemux libwebpmux tiff libavif libraqm font-dejavu utmps-libs
COPY --from=native /packages /tmp/native-packages
# These local packages are built above from pinned sources, not unsigned network packages.
# Normal APK metadata remains installed for package inventory and vulnerability scans.
RUN apk add --allow-untrusted --no-network /tmp/native-packages/*.apk \
    && rm -r /tmp/native-packages \
    && test ! -e /usr/lib/libxml2.so.2 \
    && addgroup -g 10001 mailsec && adduser -D -H -u 10001 -G mailsec mailsec \
    && addgroup -g 10002 clamav && adduser -D -H -u 10002 -G clamav clamav \
    && addgroup -g 10003 inspector && adduser -D -H -u 10003 -G inspector inspector \
    && addgroup -g 10004 postgres && adduser -D -H -u 10004 -G postgres postgres \
    && addgroup -g 10005 freshclam && adduser -D -H -u 10005 -G freshclam freshclam
COPY --from=python-build /wheels /tmp/wheels
RUN pip install --no-index /tmp/wheels/*.whl && pip check \
    && pip uninstall -y pip && rm -r /tmp/wheels
# Complete source inputs and the modification recipe accompany rebuilt GPL components.
COPY --from=native /sources/*.tar.* /sources/rand-0.9.3.crate /usr/share/mailsec-native/sources/
COPY --from=native /build-tools /usr/share/mailsec-native/build-tools/
COPY --from=native /sources/busybox /usr/share/mailsec-native/sources/busybox
COPY Dockerfile.selfhost /usr/share/mailsec-native/Dockerfile.selfhost
COPY deploy/native/README.md deploy/native/patches.json /usr/share/mailsec-native/
COPY deploy/native/patches /usr/share/mailsec-native/patches
COPY scripts/native_inventory.py scripts/patch_python_stdlib.py /usr/share/mailsec-native/build-tools/
RUN python /usr/share/mailsec-native/build-tools/patch_python_stdlib.py \
    /usr/local/lib/python3.12 /usr/share/mailsec-native/patches \
    /usr/share/mailsec-native/python-stdlib-patches.json
RUN apk info -vv > /usr/share/mailsec-native/apk-packages.txt \
    && python /usr/share/mailsec-native/build-tools/native_inventory.py /usr/share/mailsec-native/runtime-versions.json
COPY mailsec ./mailsec
COPY deploy/selfhost/organization.example.yaml /app/organization.yaml
COPY deploy/selfhost/clamd.conf deploy/selfhost/freshclam.conf deploy/selfhost/postgresql.conf /etc/mailsec/
COPY scripts/container_runtime.py scripts/container_health.py scripts/container_backup.py /opt/mailsec/
EXPOSE 8025
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=10m --retries=3 CMD ["python", "/opt/mailsec/container_health.py"]
ENTRYPOINT ["python", "/opt/mailsec/container_runtime.py"]
