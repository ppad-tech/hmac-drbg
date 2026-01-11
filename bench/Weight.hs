{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.DeepSeq
import qualified Crypto.DRBG.HMAC as DRBG
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Data.ByteString as BS
import Weigh

instance NFData (DRBG.DRBG s) where
  rnf d = d `seq` ()

instance NFData DRBG.Error where
  rnf e = e `seq` ()

hmac_sha256 :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmac_sha256 k b = case SHA256.hmac k b of
  SHA256.MAC m -> m

hmac_sha512 :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmac_sha512 k b = case SHA512.hmac k b of
  SHA512.MAC m -> m

-- note that 'weigh' doesn't work properly in a repl
main :: IO ()
main = do
  !drbg256 <- DRBG.new hmac_sha256 mempty mempty mempty
  !drbg512 <- DRBG.new hmac_sha512 mempty mempty mempty
  mainWith $ do
    sha256 drbg256
    sha512 drbg512

sha256 drbg = wgroup "HMAC-SHA256" $ do
  io "new" (DRBG.new hmac_sha256 mempty mempty) mempty
  io "reseed" (DRBG.reseed mempty mempty) drbg
  io "gen (32B)" (DRBG.gen mempty 32) drbg
  io "gen (256B)" (DRBG.gen mempty 256) drbg

sha512 drbg = wgroup "HMAC-SHA512" $ do
  io "new" (DRBG.new hmac_sha512 mempty mempty) mempty
  io "reseed" (DRBG.reseed mempty mempty) drbg
  io "gen (32B)" (DRBG.gen mempty 32) drbg
  io "gen (256B)" (DRBG.gen mempty 256) drbg
