#!/usr/bin/env bash
# Build fixture filesystem trees. Fixtures are plain directories that stand in
# for a system root, so tests never touch the real host.
set -Eeuo pipefail
FIX=${1:?usage: make-fixtures.sh <output-dir>}
rm -rf -- "$FIX"
mkdir -p -- "$FIX"

mk() { mkdir -p -- "$(dirname -- "$1")"; cat >"$1"; }

# ---- debian-stable (trixie) ------------------------------------------------
d="$FIX/debian-stable"
mk "$d/etc/os-release" <<'EOF'
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION="13 (trixie)"
VERSION_CODENAME=trixie
ID=debian
EOF
echo "13.0" >"$d/etc/debian_version"
mkdir -p "$d/usr/share/keyrings" "$d/etc/apt/sources.list.d" "$d/etc/apt/trusted.gpg.d"
: >"$d/usr/share/keyrings/debian-archive-keyring.gpg"
mk "$d/etc/apt/sources.list.d/debian.sources" <<'EOF'
Types: deb
URIs: http://deb.debian.org/debian/
Suites: trixie trixie-updates
Components: main contrib
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF

# ---- ubuntu-lts (noble) ----------------------------------------------------
d="$FIX/ubuntu-lts"
mk "$d/etc/os-release" <<'EOF'
PRETTY_NAME="Ubuntu 24.04.4 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
EOF
mkdir -p "$d/usr/share/keyrings" "$d/etc/apt/sources.list.d"
: >"$d/usr/share/keyrings/ubuntu-archive-keyring.gpg"
mk "$d/etc/lsb-release" <<'EOF'
DISTRIB_ID=Ubuntu
DISTRIB_CODENAME=noble
EOF
mk "$d/etc/apt/sources.list.d/ubuntu.sources" <<'EOF'
Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: noble noble-updates
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: noble-security
Components: main universe
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
EOF

# ---- kali-purple -----------------------------------------------------------
d="$FIX/kali-purple"
mk "$d/etc/os-release" <<'EOF'
PRETTY_NAME="Kali GNU/Linux Purple Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2026.2"
VERSION="2026.2"
ID=kali
ID_LIKE=debian
EOF
mkdir -p "$d/usr/share/keyrings" "$d/etc/apt/sources.list.d" "$d/usr/share/kali-purple"
: >"$d/usr/share/keyrings/kali-archive-keyring.gpg"
mk "$d/etc/apt/sources.list.d/kali.sources" <<'EOF'
Types: deb
URIs: http://http.kali.org/kali/
Suites: kali-last-snapshot
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/kali-archive-keyring.gpg
EOF

# ---- parrot ----------------------------------------------------------------
d="$FIX/parrot"
mk "$d/etc/os-release" <<'EOF'
PRETTY_NAME="Parrot Security 7.0 (echo)"
NAME="Parrot Security"
VERSION_ID="7.0"
VERSION_CODENAME=echo
ID=parrot
ID_LIKE=debian
EOF
mkdir -p "$d/etc/apt/sources.list.d" "$d/etc/apt/trusted.gpg.d" "$d/usr/share/parrot-menu"
: >"$d/etc/apt/trusted.gpg.d/parrot-archive-keyring.gpg"
mk "$d/etc/apt/sources.list.d/parrot.list" <<'EOF'
deb https://deb.parrot.sh/parrot echo main contrib non-free non-free-firmware
deb https://deb.parrot.sh/direct/parrot echo-security main contrib non-free non-free-firmware
EOF

# ---- mx-linux --------------------------------------------------------------
d="$FIX/mx-linux"
mk "$d/etc/os-release" <<'EOF'
PRETTY_NAME="MX 25 (Infinity)"
NAME="MX"
VERSION_ID="25"
VERSION="25 (Infinity)"
ID=mx
ID_LIKE=debian
EOF
echo "13.3" >"$d/etc/debian_version"
echo "MX-25_x64 Infinity" >"$d/etc/mx-version"
mkdir -p "$d/etc/apt/sources.list.d" "$d/etc/init.d" "$d/usr/share/mx-packageinstaller"
: >"$d/etc/inittab"
mk "$d/etc/apt/sources.list.d/mx.list" <<'EOF'
deb http://mirror.example.org/mx/repo/ trixie main non-free
EOF
mk "$d/etc/apt/sources.list.d/debian.list" <<'EOF'
deb http://deb.debian.org/debian trixie main contrib non-free
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
EOF

# ---- termux ----------------------------------------------------------------
d="$FIX/termux"
mkdir -p "$d/data/data/com.termux/files/usr/etc/apt/sources.list.d"
mkdir -p "$d/data/data/com.termux/files/usr/etc/apt/trusted.gpg.d"
mkdir -p "$d/data/data/com.termux/files/usr/share/termux-keyring"
mkdir -p "$d/data/data/com.termux/files/usr/bin"
: >"$d/data/data/com.termux/files/usr/bin/pkg"
chmod +x "$d/data/data/com.termux/files/usr/bin/pkg"
: >"$d/data/data/com.termux/files/usr/share/termux-keyring/termux-autobuilds.gpg"
ln -sf ../../share/termux-keyring/termux-autobuilds.gpg \
   "$d/data/data/com.termux/files/usr/etc/apt/trusted.gpg.d/termux-autobuilds.gpg"
mk "$d/data/data/com.termux/files/usr/etc/apt/sources.list" <<'EOF'
deb https://packages.termux.dev/apt/termux-main stable main
EOF

# ---- unknown-derivative ----------------------------------------------------
d="$FIX/unknown-derivative"
mk "$d/etc/os-release" <<'EOF'
PRETTY_NAME="ExampleOS 3"
NAME="ExampleOS"
VERSION_ID="3"
VERSION_CODENAME=example
ID=exampleos
ID_LIKE=debian
EOF
mkdir -p "$d/etc/apt/sources.list.d"
mk "$d/etc/apt/sources.list" <<'EOF'
deb http://packages.example.org/exampleos example main
EOF

# ---- ambiguous (Kali + Parrot evidence on one system) ----------------------
d="$FIX/ambiguous"
mk "$d/etc/os-release" <<'EOF'
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
VERSION_ID="2026.2"
ID=kali
ID_LIKE=debian
EOF
mkdir -p "$d/usr/share/keyrings" "$d/etc/apt/sources.list.d"
: >"$d/usr/share/keyrings/kali-archive-keyring.gpg"
: >"$d/etc/apt/sources.list.d/parrot.list"

# ---- eol-release (Ubuntu 25.10 questing, EOL 2026-07-09) -------------------
d="$FIX/eol-release"
mk "$d/etc/os-release" <<'EOF'
PRETTY_NAME="Ubuntu 25.10"
NAME="Ubuntu"
VERSION_ID="25.10"
VERSION_CODENAME=questing
ID=ubuntu
ID_LIKE=debian
EOF
mkdir -p "$d/usr/share/keyrings" "$d/etc/apt/sources.list.d" "$d/usr/share/distro-info"
: >"$d/usr/share/keyrings/ubuntu-archive-keyring.gpg"
mk "$d/etc/lsb-release" <<'EOF'
DISTRIB_ID=Ubuntu
DISTRIB_CODENAME=questing
EOF
mk "$d/usr/share/distro-info/ubuntu.csv" <<'EOF'
version,codename,series,created,release,eol,eol-server,eol-esm
24.04 LTS,Noble Numbat,noble,2023-10-12,2024-04-25,2029-05-31,2029-05-31,2034-04-25
25.10,Questing Quokka,questing,2025-04-17,2025-10-09,2026-07-09
EOF

# ---- hostile: hooks, trusted=yes, foreign repos, traversal, symlink --------
d="$FIX/hostile"
mk "$d/etc/os-release" <<'EOF'
PRETTY_NAME="Debian GNU/Linux 13 (trixie)"
NAME="Debian GNU/Linux"
VERSION_ID="13"
VERSION_CODENAME=trixie
ID=debian
EOF
mkdir -p "$d/etc/apt/sources.list.d" "$d/etc/apt/apt.conf.d" "$d/etc/apt/preferences.d" \
         "$d/usr/share/keyrings" "$d/etc/apt/trusted.gpg.d" "$d/secret"
: >"$d/usr/share/keyrings/debian-archive-keyring.gpg"
echo "top secret" >"$d/secret/data"
mk "$d/etc/apt/sources.list" <<'EOF'
deb [trusted=yes] http://evil.example.net/debian trixie main
deb http://deb.debian.org/debian trixie main
deb http://deb.debian.org/debian trixie main
deb http://http.kali.org/kali kali-rolling main
deb http://deb.debian.org/debian sid main
EOF
mk "$d/etc/apt/apt.conf.d/99-hostile" <<'EOF'
DPkg::Pre-Invoke {"/tmp/payload.sh";};
Acquire::http::Proxy "http://user:hunter2@proxy.example.net:3128";
APT::Get::AllowUnauthenticated "true";
EOF
chmod +x "$d/etc/apt/apt.conf.d/99-hostile"
mk "$d/etc/apt/preferences.d/pin-old" <<'EOF'
Package: openssl
Pin: version 1.*
Pin-Priority: 1001
EOF
ln -sf ../../../secret/data "$d/etc/apt/trusted.gpg.d/escape.gpg"

printf 'fixtures written to %s\n' "$FIX"
