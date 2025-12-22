{
  description = "Pure Haskell HMAC-DRBG";

  inputs = {
    ppad-nixpkgs = {
      type = "git";
      url  = "git://git.ppad.tech/nixpkgs.git";
      ref  = "master";
    };
    ppad-base16 = {
      type = "git";
      url  = "git://git.ppad.tech/base16.git";
      ref  = "master";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-sha256 = {
      type = "git";
      url  = "git://git.ppad.tech/sha256.git";
      ref  = "master";
      inputs.ppad-base16.follows = "ppad-base16";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    ppad-sha512 = {
      type = "git";
      url  = "git://git.ppad.tech/sha512.git";
      ref  = "master";
      inputs.ppad-base16.follows = "ppad-base16";
      inputs.ppad-nixpkgs.follows = "ppad-nixpkgs";
    };
    flake-utils.follows = "ppad-nixpkgs/flake-utils";
    nixpkgs.follows = "ppad-nixpkgs/nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, ppad-nixpkgs
            , ppad-base16, ppad-sha256, ppad-sha512
            }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        lib = "ppad-hmac-drbg";

        pkgs = import nixpkgs { inherit system; };
        hlib = pkgs.haskell.lib;
        llvm = pkgs.llvmPackages_15.llvm;

        base16 = ppad-base16.packages.${system}.default;
        sha512 = ppad-sha512.packages.${system}.default;

        sha256 = ppad-sha256.packages.${system}.default;
        sha256-llvm =
          hlib.addBuildTools
            (hlib.enableCabalFlag sha256 "llvm")
            [ llvm ];

        hpkgs = pkgs.haskell.packages.ghc981.extend (new: old: {
          ppad-base16 = base16;
          ppad-sha256 = sha256-llvm;
          ppad-sha512 = sha512;
          ${lib} = new.callCabal2nix lib ./. {
            ppad-base16 = new.ppad-base16;
            ppad-sha256 = new.ppad-sha256;
            ppad-sha512 = new.ppad-sha512;
          };
        });

        cc    = pkgs.stdenv.cc;
        ghc   = hpkgs.ghc;
        cabal = hpkgs.cabal-install;
      in
        {
          packages.default = hpkgs.${lib};

          devShells.default = hpkgs.shellFor {
            packages = p: [
              (hlib.doBenchmark p.${lib})
            ];

            buildInputs = [
              cabal
              cc
              llvm
            ];

            inputsFrom = builtins.attrValues self.packages.${system};

            doBenchmark = true;

            shellHook = ''
              PS1="[${lib}] \w$ "
              echo "entering ${system} shell, using"
              echo "cc:    $(${cc}/bin/cc --version)"
              echo "ghc:   $(${ghc}/bin/ghc --version)"
              echo "cabal: $(${cabal}/bin/cabal --version)"
              echo "llc:   $(${llvm}/bin/llc --version | head -2 | tail -1)"
            '';
          };
        }
      );
}

