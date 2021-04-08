{
  description = "Скрипт для анализа логов и управления фильтрами";

  inputs = {
    nixpkgs-unstable.url = "nixpkgs/nixpkgs-unstable";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };

    nixpkgs.url = "nixpkgs/nixos-20.09";

    majordomo.url = "git+https://gitlab.intr/_ci/nixpkgs";
  };

  outputs = { self, nixpkgs, nixpkgs-unstable, majordomo, ... } @ inputs:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      pkgs-unstable = import nixpkgs-unstable { inherit system; };
    in {
      packages.${system} = rec {
        cymruwhois = pkgs.callPackage ({ python3, python3Packages }: python3.pkgs.buildPythonPackage rec {
          pname = "cymruwhois";
          version = "1.6";
          src = python3.pkgs.fetchPypi {
            inherit pname version;
            sha256 = "0m7jgpglkjd0lsyw64lfw6qxdm0fg0f54145f79kq4rk1vjqbh5n";
          };
          checkInputs = with python3Packages; [
            nose
          ];
        }) {};
        pacifier = with pkgs; callPackage ({ python3, python3Packages }: python3.pkgs.buildPythonPackage {
          pname = "pacifier";
          version = "0.0.1";
          src = ./.;
          doCheck = false; # TODO: Could we implement a test suite?
          propagatedBuildInputs = with python3Packages; [
            cymruwhois
            elasticsearch
            python-json-logger
            requests
          ];
        }) {
          python3Packages = python3Packages // { inherit cymruwhois; };
        };
        container = import ./default.nix {
          pkgs = majordomo.outputs.nixpkgs;
          inherit (majordomo.packages.${system}) nss-certs;
          inherit pacifier;
        };
        deploy = majordomo.outputs.deploy { tag = "net/pacifier"; };
      };

      defaultPackage.${system} = self.packages.${system}.container;

      devShell.${system} = with pkgs-unstable; mkShell {
        buildInputs = [ nixUnstable self.packages.${system}.pacifier ];
      };
    };
}
