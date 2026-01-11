{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import qualified Crypto.DRBG.HMAC.SHA256 as DRBG

main :: IO ()
main = do
  !drbg256 <- DRBG.new mempty mempty mempty
  -- !drbg512 <- DRBG.new mempty mempty mempty
  defaultMain [
      suite drbg256
    ]

suite drbg256 =
  bgroup "ppad-hmac-drbg" [
    bgroup "HMAC-SHA256" [
      bench "new" $ whnfAppIO (DRBG.new mempty mempty) mempty
    , bench "reseed" $ whnfAppIO (DRBG.reseed drbg256 mempty) mempty
    , bench "gen (32B)"  $ whnfAppIO (DRBG.gen drbg256 mempty) 32
    , bench "gen (256B)" $ whnfAppIO (DRBG.gen drbg256 mempty) 256
    ]
  -- , bgroup "HMAC-SHA512" [
  --     bench "new" $ whnfAppIO (DRBG.new mempty mempty) mempty
  --   , bench "reseed" $ whnfAppIO (DRBG.reseed drbg512 mempty) mempty
  --   , bench "gen (32B)"  $ whnfAppIO (DRBG.gen drbg512 mempty) 32
  --   , bench "gen (256B)" $ whnfAppIO (DRBG.gen drbg512 mempty) 256
  --   ]
  ]

