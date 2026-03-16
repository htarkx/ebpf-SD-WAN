{
  description = "XDP/eBPF devShell (pure unwrapped clang, explicit headers)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib  = pkgs.lib;
        llvm = pkgs.llvmPackages_latest;

        # Header paths needed for libpcap/libelf and friends.
        includes = [
          "${pkgs.glibc.dev}/include"
          "${pkgs.pkgsi686Linux.glibc.dev}/include"
          "${pkgs.linuxHeaders}/include"
          "${pkgs.libbpf}/include"
          "${pkgs.xdp-tools}/include"
          "${pkgs.libpcap}/include"  # Fixes missing pcap.h
          "${pkgs.libelf}/include"   # Keep libelf headers in path
        ];

        cIncludePath = lib.concatStringsSep ":" includes;

        pkgConfigPath = lib.makeSearchPathOutput "lib" "pkgconfig" [
          pkgs.libbpf
          pkgs.libelf
          pkgs.libpcap
          pkgs.zlib
          pkgs.elfutils
        ];

        bpfArch = "-D__TARGET_ARCH_x86";
        libraryPath = lib.makeLibraryPath [
          pkgs.glibc
          pkgs.pkgsi686Linux.glibc
          pkgs.libbpf
          pkgs.libelf
          pkgs.libpcap
          pkgs.zlib
        ];

      in
      {
        devShells.default = pkgs.mkShell {
          name = "xdp-ebpf-shell";

          packages = with pkgs; [
            llvm.clang-unwrapped
            llvm.clang-tools
            llvm.llvm
            gnumake
            pkg-config
            bear
            m4
            glibc.dev
            pkgsi686Linux.glibc.dev
            linuxHeaders
            bpftools
            libbpf
            xdp-tools
            elfutils
            libelf
            libpcap
            iproute2
            ethtool
            pahole
            perf
            tcpdump
            zlib
            go             
            gopls        
            delve    
            gotools
          ];

          shellHook = ''
            echo "== XDP/eBPF dev shell (pure unwrapped clang) =="

            export CLANG="${llvm.clang-unwrapped}/bin/clang"
            export CC="$CLANG"
            export CXX="$CLANG++"

            # Header search paths for Clang.
            export C_INCLUDE_PATH="${cIncludePath}"
            export CPLUS_INCLUDE_PATH="${cIncludePath}"

            # Library search paths for libpcap/libelf, etc.
            export LIBRARY_PATH="${libraryPath}"

            export CLANG_SYSINC="$($CLANG -print-resource-dir)/include"

            export KERNEL_HEADERS="${pkgs.linuxHeaders}/include"
            export LIBBPF_HEADERS="${pkgs.libbpf}/include"

            export BPF_CFLAGS="-O2 -g -target bpf ${bpfArch} \
              -isystem $CLANG_SYSINC \
              -I$KERNEL_HEADERS/uapi \
              -I$KERNEL_HEADERS/uapi/linux \
              -I$KERNEL_HEADERS/uapi/asm-generic \
              -I$KERNEL_HEADERS/asm-generic"

            export PKG_CONFIG_PATH="${pkgConfigPath}:$PKG_CONFIG_PATH"
            export NIX_HARDENING_ENABLE=""

            alias bpf-clang='$CLANG $BPF_CFLAGS'
            alias gen-vmlinux-h='bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h'

            echo "Environment updated. Ready to compile."
          '';
        };
      }
    );
}
