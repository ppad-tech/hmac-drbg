{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import qualified Crypto.DRBG.HMAC as DRBG
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA512 as SHA512

main :: IO ()
main = do
  !drbg256 <- DRBG.new SHA256.hmac mempty mempty mempty -- no NFData
  !drbg512 <- DRBG.new SHA512.hmac mempty mempty mempty -- no NFData
  defaultMain [
      suite drbg256 drbg512
    ]

suite drbg256 drbg512 =
  bgroup "ppad-hmac-drbg" [
    bgroup "HMAC-SHA256" [
      bench "new" $ whnfAppIO (DRBG.new SHA256.hmac mempty mempty) mempty
    , bench "reseed" $ whnfAppIO (DRBG.reseed mempty mempty) drbg256
    , bench "gen (32B)"  $ nfAppIO (DRBG.gen mempty 32) drbg256
    , bench "gen (256B)" $ nfAppIO (DRBG.gen mempty 256) drbg256
    ]
  , bgroup "HMAC-SHA512" [
      bench "new" $ whnfAppIO (DRBG.new SHA512.hmac mempty mempty) mempty
    , bench "reseed" $ whnfAppIO (DRBG.reseed mempty mempty) drbg512
    , bench "gen (32B)"  $ nfAppIO (DRBG.gen mempty 32) drbg512
    , bench "gen (256B)" $ nfAppIO (DRBG.gen mempty 256) drbg512
    ]
  ]

