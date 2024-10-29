{
  inputs = {
    nixpkgs = { url = "github:NixOS/nixpkgs/nixos-unstable"; };
    systems.url = "github:nix-systems/default";
  };

  outputs = { self, nixpkgs, systems, ... }@inputs:
    let
      eachSystem = f:
        nixpkgs.lib.genAttrs (import systems) (system:
          f (import nixpkgs {
            inherit system;
            config = { allowUnfree = true; };
            overlays = [ ];
          }));
    in {

      devShells = eachSystem (pkgs: {
        default = pkgs.mkShell {
          hardeningDisable = [ "all" ];
          buildInputs = [ ];

          packages = [
            pkgs.delve
            pkgs.gcc
            pkgs.gh
            pkgs.go_1_23
            pkgs.gotools
            pkgs.gopls
            pkgs.go-outline
            pkgs.gopkgs
            pkgs.godef
            pkgs.golangci-lint
            pkgs.go-tools
            pkgs.gitAndTools.git-absorb
            pkgs.treefmt
          ];
        };
      });
    };
}