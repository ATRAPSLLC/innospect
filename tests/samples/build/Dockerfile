# syntax=docker/dockerfile:1
#
# Every Inno Setup compiler the fixtures are built with, under Wine.
#
# `build-wine.sh` builds this image on first use (and whenever this file,
# `versions.txt` or `install-inno.sh` changes) and runs it with this directory
# bind-mounted, so an `.iss` edit needs no image rebuild.
#
# Arch rather than Debian because its Wine is the "new WoW64" build: it runs
# a 32-bit PE - `ISCC.exe` is one - with no 32-bit Linux userspace at all
# (securs measured and pinned the same base for the same reason).
FROM archlinux:base

# Xvfb because Setup creates windows even when silent, and Wine has no display
# driver to create them on without one: the install fails with "A call to an
# OS function failed".
RUN pacman -Syu --noconfirm --needed wine curl xorg-server-xvfb \
    && pacman -Scc --noconfirm

# The prefix, provisioned once here rather than on every compile.
ENV WINEPREFIX=/opt/wine
ENV WINEDEBUG=-all
RUN wineboot -u && wineserver -w

# The compiler matrix, one directory per version: `C:\inno\<slug>`.
COPY versions.txt install-inno.sh /opt/inno-setup/
RUN /opt/inno-setup/install-inno.sh /opt/inno-setup/versions.txt
