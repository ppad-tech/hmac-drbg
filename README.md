# ppad-hmac-drbg

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

Current benchmark figures on my mid-2020 MacBook Air look like (use
`cabal bench` to run the benchmark suite):

```
  benchmarking ppad-hmac-drbg/HMAC-SHA256/new
  time                 20.86 μs   (20.78 μs .. 20.94 μs)
                       1.000 R²   (1.000 R² .. 1.000 R²)
  mean                 20.82 μs   (20.72 μs .. 20.93 μs)
  std dev              370.6 ns   (299.3 ns .. 456.6 ns)
  variance introduced by outliers: 15% (moderately inflated)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/reseed
  time                 13.98 μs   (13.83 μs .. 14.18 μs)
                       0.999 R²   (0.998 R² .. 1.000 R²)
  mean                 13.89 μs   (13.79 μs .. 14.03 μs)
  std dev              398.9 ns   (296.7 ns .. 580.8 ns)
  variance introduced by outliers: 32% (moderately inflated)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/gen (32B)
  time                 21.10 μs   (20.95 μs .. 21.25 μs)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 21.19 μs   (21.06 μs .. 21.36 μs)
  std dev              509.2 ns   (390.7 ns .. 812.2 ns)
  variance introduced by outliers: 24% (moderately inflated)

  benchmarking ppad-hmac-drbg/HMAC-SHA256/gen (256B)
  time                 68.17 μs   (67.62 μs .. 68.82 μs)
                       1.000 R²   (0.999 R² .. 1.000 R²)
  mean                 68.74 μs   (68.42 μs .. 69.09 μs)
  std dev              1.172 μs   (1.022 μs .. 1.410 μs)
  variance introduced by outliers: 12% (moderately inflated)
```

## Security

This library aims at the maximum security achievable in a
garbage-collected language under an optimizing compiler such as GHC, in
which strict constant-timeness can be challenging to achieve.

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
