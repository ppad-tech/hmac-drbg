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
  time                 10.46 μs   (10.45 μs .. 10.46 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 10.44 μs   (10.44 μs .. 10.46 μs)
  std dev              28.45 ns   (19.59 ns .. 46.15 ns)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/reseed
  time                 6.917 μs   (6.900 μs .. 6.934 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 6.908 μs   (6.893 μs .. 6.921 μs)
  std dev              47.40 ns   (27.59 ns .. 84.31 ns)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/gen (32B)
  time                 10.55 μs   (10.52 μs .. 10.59 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 10.51 μs   (10.50 μs .. 10.53 μs)
  std dev              44.48 ns   (25.76 ns .. 78.90 ns)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/gen (256B)
  time                 36.08 μs   (34.94 μs .. 37.26 μs)
                       0.996 R²   (0.994 R² .. 1.000 R²)
  mean                 35.30 μs   (35.09 μs .. 35.96 μs)
  std dev              1.085 μs   (488.0 ns .. 2.012 μs)
```

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
