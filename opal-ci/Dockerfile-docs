FROM fedora:27
RUN dnf -y install wget curl xterm gcc git xz make diffutils findutils expect valgrind valgrind-devel ccache dtc openssl-devel
COPY . /build/
WORKDIR /build
