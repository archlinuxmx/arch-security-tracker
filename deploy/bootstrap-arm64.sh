#!/bin/sh
set -eu
umask 022

rootfs=${1:-/rootfs}
archive_url=${ARCH_ARM_ROOTFS_URL:-https://fl.us.mirror.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz}
fingerprint=68B3537F39A313B3E574D06777193F152BDBE6A6
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

mkdir -p "$rootfs"
if [ -n "$(ls -A "$rootfs")" ]; then
    echo "Root filesystem destination must be empty: $rootfs" >&2
    exit 1
fi

fetch() {
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 20 --max-time 900 \
        --output "$2" "$1"
}

fetch "$archive_url" "$temporary/rootfs.tar.gz"
fetch "$archive_url.sig" "$temporary/rootfs.tar.gz.sig"
fetch "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$fingerprint" \
    "$temporary/build-key.asc"

# Accept only the release key whose fingerprint Arch Linux ARM publishes.
mkdir -m 700 "$temporary/gnupg"
gpg --batch --homedir "$temporary/gnupg" --with-colons \
    --show-keys "$temporary/build-key.asc" > "$temporary/key-info"
key_count=$(awk -F: '$1 == "pub" { count++ } END { print count + 0 }' "$temporary/key-info")
actual_fingerprint=$(awk -F: '$1 == "fpr" { print $10; exit }' "$temporary/key-info")
if [ "$key_count" -ne 1 ] || [ "$actual_fingerprint" != "$fingerprint" ]; then
    echo 'Unexpected Arch Linux ARM release key' >&2
    exit 1
fi
gpg --batch --homedir "$temporary/gnupg" --dearmor \
    --output "$temporary/release-key.gpg" "$temporary/build-key.asc"
gpgv --homedir "$temporary/gnupg" --keyring "$temporary/release-key.gpg" \
    "$temporary/rootfs.tar.gz.sig" "$temporary/rootfs.tar.gz"

if [ -n "${ARCH_ARM_ROOTFS_SHA256:-}" ]; then
    printf '%s  %s\n' "$ARCH_ARM_ROOTFS_SHA256" "$temporary/rootfs.tar.gz" \
        | sha256sum --check --status
fi

bsdtar --no-same-owner --no-same-permissions --no-xattrs --no-acls \
    -xf "$temporary/rootfs.tar.gz" -C "$rootfs" \
    --exclude './dev/*' --exclude 'dev/*'
mkdir -p "$rootfs/dev"
chmod 1777 "$rootfs/tmp" "$rootfs/var/tmp"

# The hardware image ships login passwords; containers have no login accounts.
awk -F: 'BEGIN { OFS = ":" } $1 == "root" || $1 == "alarm" { $2 = "!" } { print }' \
    "$rootfs/etc/shadow" > "$temporary/shadow"
cat "$temporary/shadow" > "$rootfs/etc/shadow"
awk -F: 'BEGIN { OFS = ":" } $1 == "root" || $1 == "alarm" { $7 = "/usr/bin/nologin" } { print }' \
    "$rootfs/etc/passwd" > "$temporary/passwd"
cat "$temporary/passwd" > "$rootfs/etc/passwd"
rm -rf "$rootfs/root/.ssh" "$rootfs/home/alarm/.ssh"
rm -f "$rootfs/etc/ssh/"ssh_host_* "$rootfs/etc/resolv.conf" "$rootfs/etc/machine-id"
: > "$rootfs/etc/resolv.conf"
: > "$rootfs/etc/machine-id"
printf '%s\n' 'Server = https://fl.us.mirror.archlinuxarm.org/$arch/$repo' \
    > "$rootfs/etc/pacman.d/mirrorlist"
