{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import qualified Crypto.DRBG.HMAC.SHA256 as DRBG256
import qualified Crypto.DRBG.HMAC.SHA512 as DRBG512

main :: IO ()
main = do
  !drbg256 <- DRBG256.new mempty mempty mempty
  !drbg512 <- DRBG512.new mempty mempty mempty
  defaultMain [
      suite drbg256 drbg512
    ]

suite drbg256 drbg512 =
  bgroup "ppad-hmac-drbg" [
    bgroup "HMAC-SHA256" [
      bench "new" $ whnfAppIO (DRBG256.new mempty mempty) mempty
    , bench "reseed" $ whnfAppIO (DRBG256.reseed drbg256 mempty) mempty
    , bench "gen (32B)"  $ whnfAppIO (DRBG256.gen drbg256 mempty) 32
    , bench "gen (256B)" $ whnfAppIO (DRBG256.gen drbg256 mempty) 256
    ]
  , bgroup "HMAC-SHA512" [
      bench "new" $ whnfAppIO (DRBG512.new mempty mempty) mempty
    , bench "reseed" $ whnfAppIO (DRBG512.reseed drbg512 mempty) mempty
    , bench "gen (32B)"  $ whnfAppIO (DRBG512.gen drbg512 mempty) 32
    , bench "gen (256B)" $ whnfAppIO (DRBG512.gen drbg512 mempty) 256
    ]
  ]

