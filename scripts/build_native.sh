#!/bin/sh
# Invoked only in the disposable image-builder stage. Inputs are SHA-256 pinned.
set -eu
component=$1
mkdir -p /build /packages /pkg
cd /build

package() {
    name=$1 version=$2 license=$3 url=$4
    apk mkpkg --files "/pkg/$name" --xattrs=no \
        --info "name:$name" --info "version:$version-r100" \
        --info "origin:$name" --info "arch:$(apk --print-arch)" \
        --info "license:$license" --info "url:$url" \
        --info "description:Mailsec checksum-verified upstream source build of $name" \
        --output "/packages/$name.apk"
}

case "$component" in
    libxml2)
        tar -xf /sources/libxml2-2.15.4.tar.xz
        cd libxml2-2.15.4
        ./configure --prefix=/usr --without-python --with-legacy --disable-static
        make -j4
        make check
        make install
        make DESTDIR=/pkg/libxml2 install
        package libxml2 2.15.4 MIT https://gitlab.gnome.org/GNOME/libxml2
        ;;
    postgresql18)
        tar -xf /sources/postgresql-18.6.tar.bz2
        cd postgresql-18.6
        ./configure --prefix=/usr/lib/postgresql/18 --libdir=/usr/lib \
            --with-openssl --with-libxml --with-icu --with-lz4 --with-zstd
        make -j4
        make install
        make DESTDIR=/pkg/postgresql18 install
        package postgresql18 18.6 PostgreSQL https://www.postgresql.org
        ;;
    tesseract-ocr)
        tar -xf /sources/tesseract-565e3bd72a0ecc4814ccffbda3f17afcb40d75ef.tar.gz
        cmake -S tesseract-565e3bd72a0ecc4814ccffbda3f17afcb40d75ef -B tesseract-build -G Ninja \
            -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
            -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_TRAINING_TOOLS=OFF \
            -DGRAPHICS_DISABLED=ON -DDISABLE_ARCHIVE=ON -DDISABLE_CURL=ON \
            -DBUILD_TESTS=ON -DUSE_SYSTEM_GTEST=ON -DTESSDATA_PREFIX=/usr/share
        cmake --build tesseract-build -j4 --target tesseract normproto_test \
            fullyconnected_test lstm_layer_test recoder_test genericvector_test \
            unicharset_load_test intproto_test plumbing_test
        ctest --test-dir tesseract-build --output-on-failure \
            -R '^(normproto|fullyconnected|lstm_layer|recoder|genericvector|unicharset_load|intproto|plumbing)_test$' 
        DESTDIR=/pkg/tesseract-ocr cmake --install tesseract-build
        mkdir -p /pkg/tesseract-ocr/usr/share/tessdata
        cp /sources/*.traineddata /pkg/tesseract-ocr/usr/share/tessdata/
        package tesseract-ocr 5.5.3 Apache-2.0 https://github.com/tesseract-ocr/tesseract
        ;;
    clamav)
        tar -xf /sources/clamav-1.4.6.tar.gz
        python /build-tools/patch_clamav_rand.py /build/clamav-1.4.6 /sources/rand-0.9.3.crate
        python /build-tools/patch_clamav_onenote.py /build/clamav-1.4.6 /build-tools/onenote_path_policy.rs
        # Compile and execute the exact policy module linked into the vendor crate.
        printf 'mod path_policy;\n' > /build-tools/onenote_policy_test.rs
        cp /build-tools/onenote_path_policy.rs /build-tools/path_policy.rs
        rustc --edition=2021 --test /build-tools/onenote_policy_test.rs -o /build/onenote-path-tests
        /build/onenote-path-tests
        python /build-tools/patch_clamav_loopback.py /build/clamav-1.4.6
        cmake -S clamav-1.4.6 -B clamav-build -G Ninja \
            -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
            -DCMAKE_INSTALL_LIBDIR=lib -DENABLE_DOXYGEN=OFF -DENABLE_SYSTEMD=OFF \
            -DENABLE_TESTS=ON -DENABLE_CLAMONACC=OFF -DENABLE_MILTER=OFF \
            -DENABLE_EXTERNAL_MSPACK=ON -DENABLE_JSON_SHARED=ON -DENABLE_MAN_PAGES=OFF
        cmake --build clamav-build -j4
        ctest --test-dir clamav-build --output-on-failure -j4
        DESTDIR=/pkg/clamav cmake --install clamav-build
        mkdir -p /pkg/clamav/usr/share/mailsec-native/clamav
        cp clamav-1.4.6/Cargo.lock /pkg/clamav/usr/share/mailsec-native/clamav/
        package clamav 1.4.6 GPL-2.0-only https://www.clamav.net
        ;;
    *) echo 'Unknown native component' >&2; exit 1 ;;
esac
