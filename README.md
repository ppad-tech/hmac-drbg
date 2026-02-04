# hmac-drbg

[![](https://img.shields.io/hackage/v/ppad-hmac-drbg?color=blue)](https://hackage.haskell.org/package/ppad-hmac-drbg)
![](https://img.shields.io/badge/license-MIT-brightgreen)
[![](https://img.shields.io/badge/haddock-hmac--drbg-lightblue)](https://docs.ppad.tech/hmac-drbg)

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
  > import qualified Crypto.DRBG.HMAC.SHA256 as DRBG
  >
  > -- instantiate a DRBG
  > let entropy = "very random"
  > let nonce = "very unused"
  > let personalization_string = "very personal"
  >
  > drbg <- DRBG.new entropy nonce personalization_string
  >
  > -- use it to generate some bytes
  >
  > fmap B16.encode <$> DRBG.gen drbg mempty 32
  Right "e4d17210810c4b343f6eae2c19e3d82395b555294b1b16a85f91dbea67e5f277"
  >
  > -- reuse the generator to get more; the state is updated automatically
  >
  > fmap B16.encode <$> DRBG.gen drbg mempty 16
  Right "5d867730d99eb5335f16b1d622f03023"
  >
  > -- this DRBG was instantiated in the IO monad:
  >
  > :t drbg
  drbg :: DRBG.DRBG ghc-prim:GHC.Prim.RealWorld
  >
  > -- but you can also use ST to keep things pure:
  >
  > import Control.Monad.ST
  >
  > :{
  ghci| let drbg_pure = DRBG.new mempty mempty mempty ::
  ghci|                   forall s. ST s (DRBG.DRBG s)
  ghci| :}
  >
  > :t drbg_pure
  drbg_pure :: ST s (DRBG.DRBG s)
  >
  > runST $ drbg_pure >>= fmap (fmap B16.encode) . (\d -> DRBG.gen d mempty 16)
  Right "b44299907e4e42aa4fded5d6153e8bac"
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
  time                 225.2 ns   (224.3 ns .. 226.4 ns)
                       0.999 R²   (0.998 R² .. 1.000 R²)
  mean                 233.4 ns   (227.9 ns .. 241.8 ns)
  std dev              23.42 ns   (12.58 ns .. 34.87 ns)
  variance introduced by outliers: 90% (severely inflated)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/reseed
  time                 211.3 ns   (210.6 ns .. 211.9 ns)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 210.7 ns   (210.3 ns .. 211.1 ns)
  std dev              1.381 ns   (1.133 ns .. 1.766 ns)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/gen (32B)
  time                 367.3 ns   (366.4 ns .. 368.3 ns)
                       0.999 R²   (0.999 R² .. 1.000 R²)
  mean                 375.9 ns   (370.3 ns .. 388.7 ns)
  std dev              28.42 ns   (13.66 ns .. 55.18 ns)
  variance introduced by outliers: 83% (severely inflated)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/gen (256B)
  time                 1.472 μs   (1.468 μs .. 1.476 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 1.470 μs   (1.465 μs .. 1.474 μs)
  std dev              15.77 ns   (12.15 ns .. 21.36 ns)
```

You should compile with the 'llvm' flag for maximum performance.

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be [challenging to achieve][const].

The HMAC-DRBG implementation within has been tested against the
NIST DRBGVS vectors available for SHA-256 and SHA-512.

DRBG internal state, which must be kept secret, is kept in a single,
pinned, heap-allocated mutable buffer. It is never copied, is guaranteed
never to be moved around by the garbage collector, and its components
are never allocated anywhere else on the heap. You should zero out the
DRBG state via the 'wipe' function when you've finished using it.

(The security properties of this library have been
examined and defended in more detail in a
[security analysis](https://ppad.tech/security-analysis-hmac-drbg) at
[ppad.tech](https://ppad.tech).)

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
