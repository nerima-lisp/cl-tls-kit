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
      url = "github:nerima-lisp/cl-crypto-kit/v0.2.2";
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
            version = "0.5.0";
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
              pkgs.sbclPackages.alexandria
              pkgs.sbclPackages.bordeaux-threads
              pkgs.sbclPackages.global-vars
              pkgs.sbclPackages.trivial-features
              pkgs.sbclPackages.trivial-garbage
              cl-weave.packages.${system}.default
            ];
            shellHook = ''
              export CL_SOURCE_REGISTRY="$PWD//:${cl-crypto-kit.outPath}/:${pkgs.sbclPackages.alexandria}/:${pkgs.sbclPackages.global-vars}/:${pkgs.sbclPackages.trivial-features}/:${pkgs.sbclPackages.trivial-garbage}/:${pkgs.sbclPackages.bordeaux-threads}/"
            '';
          };
        }
      );
      checks = forEachSystem (
        system: pkgs: {
          default = pkgs.stdenvNoCC.mkDerivation {
            pname = "cl-tls-kit-tests";
            version = "0.5.0";
            src = self;
            nativeBuildInputs = [
              pkgs.sbcl
              pkgs.openssl
              pkgs.sbclPackages.alexandria
              pkgs.sbclPackages.bordeaux-threads
              pkgs.sbclPackages.global-vars
              pkgs.sbclPackages.trivial-features
              pkgs.sbclPackages.trivial-garbage
            ];
            dontConfigure = true;
            dontBuild = true;
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              export HOME="$TMPDIR/home"
              export XDG_CACHE_HOME="$TMPDIR/cache"
              mkdir -p "$HOME" "$XDG_CACHE_HOME"
              export OPENSSL="${pkgs.openssl}/bin/openssl"
              export CL_SOURCE_REGISTRY="$PWD//:${cl-crypto-kit.outPath}/:${pkgs.sbclPackages.alexandria}/:${pkgs.sbclPackages.global-vars}/:${pkgs.sbclPackages.trivial-features}/:${pkgs.sbclPackages.trivial-garbage}/:${pkgs.sbclPackages.bordeaux-threads}/"
              ${pkgs.sbcl}/bin/sbcl --noinform --non-interactive \
                --load t/crypto-provider-check.lisp
              ${pkgs.sbcl}/bin/sbcl --noinform --non-interactive \
                --eval '(require :asdf)' \
                --eval '(asdf:load-system "cl-crypto-kit")' \
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
            runtimeInputs = [
              pkgs.sbcl
              pkgs.openssl
              pkgs.sbclPackages.alexandria
              pkgs.sbclPackages.bordeaux-threads
              pkgs.sbclPackages.global-vars
              pkgs.sbclPackages.trivial-features
              pkgs.sbclPackages.trivial-garbage
            ];
            text = ''
              export OPENSSL="${pkgs.openssl}/bin/openssl"
              export CL_SOURCE_REGISTRY="$PWD//:${cl-crypto-kit.outPath}/:${pkgs.sbclPackages.alexandria}/:${pkgs.sbclPackages.global-vars}/:${pkgs.sbclPackages.trivial-features}/:${pkgs.sbclPackages.trivial-garbage}/:${pkgs.sbclPackages.bordeaux-threads}/"
              sbcl --noinform --non-interactive --eval '(require :asdf)' --eval '(asdf:load-system "cl-crypto-kit")' --eval '(asdf:test-system "cl-tls-kit")'
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
