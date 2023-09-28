let
  unstable = import (fetchTarball https://nixos.org/channels/nixos-unstable/nixexprs.tar.xz) { };
in
{ pkgs ? import <nixpkgs> { } }:
pkgs.mkShell {
  packages = [
    unstable.delve
    pkgs.gcc
    pkgs.gh
    pkgs.go-outline
    pkgs.go-tools
    unstable.go_1_21
    pkgs.gocode
    pkgs.gocode-gomod
    pkgs.godef
    pkgs.golangci-lint
    pkgs.gopkgs
    pkgs.gopls
    pkgs.gotools
    pkgs.treefmt
    pkgs.act
    pkgs.apacheHttpd
  ];
  hardeningDisable = [ "all" ]; # to build the cross-compiler
  buildInputs = [
    # Install the latest version of Node.js and its associated packages
    pkgs.nodePackages_latest.prettier
  ];
}
