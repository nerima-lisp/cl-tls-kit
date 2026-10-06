{
  description = "Strict DER and PEM building blocks for Common Lisp TLS tooling.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    cl-weave = {
      url = "github:nerima-lisp/cl-weave/v1.3.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The crypto kit is consumed by the certificate verifier when available.
    cl-crypto-kit = {
      url = "github:nerima-lisp/cl-crypto-kit/bb93f974b2d81c67a21b4f87206c81d051eee518";
      flake = false;
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      cl-weave,
      cl-crypto-kit,
      ...
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forEachSystem =
        f: nixpkgs.lib.genAttrs systems (system: f system (import nixpkgs { inherit system; }));
    in
    {
      formatter = forEachSystem (system: pkgs: pkgs.nixfmt-tree);
      packages = forEachSystem (
        system: pkgs: {
          default = pkgs.stdenvNoCC.mkDerivation {
            pname = "cl-tls-kit";
            version = "0.1.0";
            src = self;
            dontBuild = true;
            installPhase = ''
              mkdir -p "$out/share/common-lisp/source/cl-tls-kit"
              cp -r cl-tls-kit.asd src t README.md LICENSE "$out/share/common-lisp/source/cl-tls-kit/"
            '';
            meta.license = pkgs.lib.licenses.mit;
          };
        }
      );
      devShells = forEachSystem (
        system: pkgs: {
          default = pkgs.mkShell {
            packages = [
              pkgs.sbcl
              cl-weave.packages.${system}.default
            ];
          };
        }
      );
      checks = forEachSystem (
        system: pkgs: {
          default = pkgs.stdenvNoCC.mkDerivation {
            pname = "cl-tls-kit-tests";
            version = "0.1.0";
            src = self;
            nativeBuildInputs = [ pkgs.sbcl pkgs.openssl ];
            dontConfigure = true;
            dontBuild = true;
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              export HOME="$TMPDIR/home"
              export XDG_CACHE_HOME="$TMPDIR/cache"
              mkdir -p "$HOME" "$XDG_CACHE_HOME"
              export OPENSSL="${pkgs.openssl}/bin/openssl"
              export CL_SOURCE_REGISTRY="$PWD//:${cl-crypto-kit.outPath}/"
              ${pkgs.sbcl}/bin/sbcl --noinform --non-interactive \
                --load t/crypto-provider-check.lisp
              ${pkgs.sbcl}/bin/sbcl --noinform --non-interactive \
                --eval '(require :asdf)' \
                --eval '(asdf:test-system "cl-tls-kit")'
              runHook postCheck
            '';
            installPhase = ''
              mkdir -p "$out"
              touch "$out/passed"
            '';
          };
        }
      );
      apps = forEachSystem (
        system: pkgs:
        let
          test = pkgs.writeShellApplication {
            name = "cl-tls-kit-test";
            runtimeInputs = [ pkgs.sbcl pkgs.openssl ];
            text = ''
              export OPENSSL="${pkgs.openssl}/bin/openssl"
              export CL_SOURCE_REGISTRY="$PWD//:${cl-crypto-kit.outPath}/"
              sbcl --noinform --non-interactive --eval '(require :asdf)' --eval '(asdf:test-system "cl-tls-kit")'
            '';
          };
        in
        {
          default = {
            type = "app";
            program = "${test}/bin/cl-tls-kit-test";
          };
        }
      );
    };
}
