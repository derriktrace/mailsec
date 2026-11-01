#!/bin/sh
# Pinned Alpine config and all distro patches; change only wget URL validation.
set -eu
inputs=/sources/busybox
source=/build/mailsec-busybox-source
dynamic=/build/mailsec-busybox-dynamic
mkdir -p /build /packages /pkg "$source" "$dynamic"
# Explicit validation remains active under Python -O: verify every source hash,
# byte count and filename, plus the complete pinned Alpine patch order.
patches=$(python /build-tools/patch_busybox_wget.py --patch-list /build-tools/busybox.lock.json "$inputs")
tar -xf "$inputs/busybox-1.37.0.tar.bz2" -C "$source" --strip-components=1
for patch in $patches; do
    patch -d "$source" -p1 < "$inputs/$patch"
done
python /build-tools/patch_busybox_wget.py "$source"
cp "$inputs/busyboxconfig" "$dynamic/.config"
make -C "$source" O="$dynamic" silentoldconfig
extra_cflags=$(pkg-config --cflags --static libutmps)
extra_libs=$(pkg-config --libs --static libutmps)
make -C "$dynamic" -j4 CONFIG_EXTRA_CFLAGS="$extra_cflags" CONFIG_EXTRA_LDLIBS="$extra_libs"
# Validate actual executable behavior before constructing the replacement APK.
python /build-tools/check_busybox_wget.py "$dynamic/busybox"
# Keep the distro's complete applet set, not a reduced or static build.
/bin/busybox --list | sort > /build/busybox-original-applets
"$dynamic/busybox" --list | sort > /build/busybox-patched-applets
cmp /build/busybox-original-applets /build/busybox-patched-applets
install -Dm755 "$dynamic/busybox" /pkg/busybox/bin/busybox
install -Dm644 "$inputs/securetty" /pkg/busybox/etc/securetty
install -Dm644 "$inputs/acpid.logrotate" /pkg/busybox/etc/logrotate.d/acpid
install -Dm775 "$inputs/dad.if-up" /pkg/busybox/etc/network/if-up.d/dad
install -Dm644 "$inputs/udhcpc.conf" /pkg/busybox/etc/udhcpc/udhcpc.conf
install -Dm755 "$inputs/default.script" /pkg/busybox/usr/share/udhcpc/default.script
mkdir -p /pkg/busybox/etc/busybox-paths.d
"$dynamic/busybox" --list-path > /pkg/busybox/etc/busybox-paths.d/busybox
for phase in down post-down post-up pre-down pre-up up; do
    mkdir -p "/pkg/busybox/etc/network/if-$phase.d"
done
apk mkpkg --files /pkg/busybox --xattrs=no --info name:busybox --info version:1.37.0-r100 \
    --info origin:busybox --info "arch:$(apk --print-arch)" --info license:GPL-2.0-only \
    --info url:https://busybox.net/ --info 'depends:musl utmps-libs' --info 'provides:cmd:busybox=1.37.0-r100' \
    --info replaces:busybox-initscripts \
    --info 'description:BusyBox with Alpine r31 patches and Mailsec raw URL delimiter validation' \
    --script "post-install:$inputs/busybox.post-install" --script "post-upgrade:$inputs/busybox.post-upgrade" \
    --script "trigger:$inputs/busybox.trigger" \
    --trigger /bin --trigger /usr/bin --trigger /sbin --trigger /usr/sbin \
    --trigger '/lib/modules/*' --trigger '/usr/lib/modules/*' --output /packages/busybox.apk
# Alpine's /bin/sh provider pins the exact BusyBox package revision.
mkdir -p /pkg/busybox-binsh/bin
ln -s /bin/busybox /pkg/busybox-binsh/bin/sh
apk mkpkg --files /pkg/busybox-binsh --xattrs=no --info name:busybox-binsh --info version:1.37.0-r100 \
    --info origin:busybox --info arch:noarch --info license:GPL-2.0-only \
    --info url:https://busybox.net/ --info 'depends:busybox=1.37.0-r100' --info 'provides:/bin/sh' \
    --info 'provider-priority:100' --info 'description:Alpine BusyBox ash /bin/sh provider' \
    --output /packages/busybox-binsh.apk
# Preserve the ordinary distro HTTPS helper and matching auto-install metadata.
${CC:-gcc} ${CPPFLAGS:-} ${CFLAGS:-} $(pkg-config --cflags libcrypto libssl) \
    "$inputs/ssl_client.c" -o "$dynamic/ssl_client" ${LDFLAGS:-} $(pkg-config --libs libcrypto libssl)
install -Dm755 "$dynamic/ssl_client" /pkg/ssl_client/usr/bin/ssl_client
apk mkpkg --files /pkg/ssl_client --xattrs=no --info name:ssl_client --info version:1.37.0-r100 \
    --info origin:busybox --info "arch:$(apk --print-arch)" --info license:GPL-2.0-only \
    --info url:https://busybox.net/ --info 'depends:musl libssl3 libcrypto3' \
    --info 'provides:cmd:ssl_client=1.37.0-r100' --info 'install-if:busybox=1.37.0-r100 libssl3' \
    --info 'description:Alpine BusyBox HTTPS helper built from pinned distro source' \
    --output /packages/ssl_client.apk
