{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import qualified Crypto.DRBG.HMAC as DRBG
import qualified Crypto.Hash.SHA256 as SHA256

main :: IO ()
main = do
  !drbg <- DRBG.new SHA256.hmac mempty mempty mempty -- no NFData
  defaultMain [
      suite drbg
    ]

suite drbg =
  bgroup "ppad-hmac-drbg" [
    bgroup "HMAC-SHA256" [
      bench "new" $ whnfAppIO (DRBG.new SHA256.hmac mempty mempty) mempty
    , bench "reseed" $ whnfAppIO (DRBG.reseed mempty mempty) drbg
    , bench "gen (32B)"  $ whnfAppIO (DRBG.gen mempty 32) drbg
    , bench "gen (256B)" $ whnfAppIO (DRBG.gen mempty 256) drbg
    ]
  ]

