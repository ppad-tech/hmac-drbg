{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Criterion.Main
import qualified Crypto.DRBG.HMAC as DRBG
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Data.ByteString as BS

hmac_sha256 :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmac_sha256 k b = case SHA256.hmac k b of
  SHA256.MAC m -> m

hmac_sha512 :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmac_sha512 k b = case SHA512.hmac k b of
  SHA512.MAC m -> m

main :: IO ()
main = do
  !drbg256 <- DRBG.new hmac_sha256 mempty mempty mempty -- no NFData
  !drbg512 <- DRBG.new hmac_sha512 mempty mempty mempty -- no NFData
  defaultMain [
      suite drbg256 drbg512
    ]

suite drbg256 drbg512 =
  bgroup "ppad-hmac-drbg" [
    bgroup "HMAC-SHA256" [
      bench "new" $ whnfAppIO (DRBG.new hmac_sha256 mempty mempty) mempty
    , bench "reseed" $ whnfAppIO (DRBG.reseed mempty mempty) drbg256
    , bench "gen (32B)"  $ whnfAppIO (DRBG.gen mempty 32) drbg256
    , bench "gen (256B)" $ whnfAppIO (DRBG.gen mempty 256) drbg256
    ]
  , bgroup "HMAC-SHA512" [
      bench "new" $ whnfAppIO (DRBG.new hmac_sha512 mempty mempty) mempty
    , bench "reseed" $ whnfAppIO (DRBG.reseed mempty mempty) drbg512
    , bench "gen (32B)"  $ whnfAppIO (DRBG.gen mempty 32) drbg512
    , bench "gen (256B)" $ whnfAppIO (DRBG.gen mempty 256) drbg512
    ]
  ]

