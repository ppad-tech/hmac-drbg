# hmac-drbg

[![](https://img.shields.io/hackage/v/ppad-hmac-drbg?color=blue)](https://hackage.haskell.org/package/ppad-hmac-drbg)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-hmac-drbg-lightblue)](https://docs.ppad.tech/hmac-drbg)

A pure Haskell implementation of the HMAC-DRBG cryptographically-secure PRNG,
as specified by [NIST SP 800-90A][sp800].

## Usage

A sample GHCi session:

```
  > -- extensions/b16 import just for illustration here; not required for use
  > :set -XOverloadedStrings
  > :set -XRankNTypes
  > import qualified Data.ByteString.Base16 as B16
  >
  > -- import qualified
  > import qualified Crypto.DRBG.HMAC as DRBG
  >
  > -- supply your own HMAC function
  > import qualified Crypto.Hash.SHA256 as SHA256
  >
  > -- instantiate a DRBG
  > let entropy = "very random"
  > let nonce = "very unused"
  > let personalization_string = "very personal"
  >
  > drbg <- DRBG.new SHA256.hmac entropy nonce personalization_string
  >
  > -- use it to generate some bytes
  >
  > fmap B16.encode (DRBG.gen mempty 32 drbg)
  "e4d17210810c4b343f6eae2c19e3d82395b555294b1b16a85f91dbea67e5f277"
  >
  > -- reuse the generator to get more; the state is updated automatically
  >
  > fmap B16.encode (DRBG.gen mempty 16 drbg)
  "5d867730d99eb5335f16b1d622f03023"
  >
  > -- this DRBG was instantiated in the IO monad:
  >
  > :t drbg
  drbg :: DRBG.DRBG ghc-prim:GHC.Prim.RealWorld
  >
  > -- but you can also use use ST to keep things pure:
  >
  > import Control.Monad.ST
  >
  > :{
  ghci| let drbg_pure = DRBG.new SHA256.hmac mempty mempty mempty ::
  ghci|                   forall s. ST s (DRBG.DRBG s)
  ghci| :}
  >
  > :t drbg_pure
  drbg_pure :: ST s (DRBG.DRBG s)
  >
  > runST $ drbg_pure >>= fmap B16.encode . DRBG.gen mempty 16
  "b44299907e4e42aa4fded5d6153e8bac"
```

## Documentation

Haddocks (API documentation, etc.) are hosted at
[docs.ppad.tech/hmac-drbg][hadoc].

## Performance

The aim is best-in-class performance for pure, highly-auditable Haskell
code.

Current benchmark figures on an M4 Silicon MacBook Air look like (use
`cabal bench` to run the benchmark suite):

```
  benchmarking ppad-hmac-drbg/HMAC-SHA256/new
  time                 2.771 μs   (2.767 μs .. 2.775 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 2.768 μs   (2.764 μs .. 2.772 μs)
  std dev              12.21 ns   (10.10 ns .. 14.90 ns)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/reseed
  time                 1.777 μs   (1.776 μs .. 1.778 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 1.777 μs   (1.776 μs .. 1.778 μs)
  std dev              2.260 ns   (1.699 ns .. 3.099 ns)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/gen (32B)
  time                 2.756 μs   (2.753 μs .. 2.759 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 2.757 μs   (2.754 μs .. 2.760 μs)
  std dev              9.806 ns   (6.361 ns .. 16.87 ns)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/gen (256B)
  time                 8.967 μs   (8.959 μs .. 8.980 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 8.970 μs   (8.965 μs .. 8.985 μs)
  std dev              26.04 ns   (12.30 ns .. 52.00 ns)
```

You should compile with the 'llvm' flag (and ensure that
[ppad-sha256][sh256] has been compiled with the 'llvm' flag) for
maximum performance.

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be [challenging to achieve][const].

The HMAC-DRBG implementation within has been tested against the
NIST DRBGVS vectors available for SHA-256 and SHA-512, using the
HMAC functions from [ppad-sha256][sh256] and [ppad-sha512][sh512]
respectively.

If you discover any vulnerabilities, please disclose them via
security@ppad.tech.

## Development

You'll require [Nix][nixos] with [flake][flake] support enabled. Enter a
development shell with:

```
$ nix develop
```

Then do e.g.:

```
$ cabal repl ppad-hmac-drbg
```

to get a REPL for the main library.

[sp800]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf
[nixos]: https://nixos.org/
[flake]: https://nixos.org/manual/nix/unstable/command-ref/new-cli/nix3-flake.html
[hadoc]: https://docs.ppad.tech/hmac-drbg
[sh256]: https://git.ppad.tech/sha256
[sh512]: https://git.ppad.tech/sha512
[const]: https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html
