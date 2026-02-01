{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- NOTE: weigh forks a subprocess per test, so each test pays ~32KB of
-- process initialization overhead. Direct measurement via GHC.Stats
-- shows actual per-call allocation is ~1.1KB for DRBG.new.

module Main where

import Control.DeepSeq
import qualified Crypto.DRBG.HMAC.SHA256 as DRBG256
import qualified Crypto.DRBG.HMAC.SHA512 as DRBG512
import Weigh

instance NFData (DRBG256.DRBG s) where
  rnf d = d `seq` ()

instance NFData DRBG256.Error where
  rnf e = e `seq` ()

instance NFData (DRBG512.DRBG s) where
  rnf d = d `seq` ()

instance NFData DRBG512.Error where
  rnf e = e `seq` ()

main :: IO ()
main = do
  !drbg256 <- DRBG256.new mempty mempty mempty
  !drbg512 <- DRBG512.new mempty mempty mempty
  mainWith $ do
    wgroup "HMAC-SHA256" $ do
      io "new" (DRBG256.new mempty mempty) mempty
      io "reseed" (DRBG256.reseed drbg256 mempty) mempty
      io "gen (32B)" (DRBG256.gen drbg256 mempty) 32
      io "gen (256B)" (DRBG256.gen drbg256 mempty) 256
    wgroup "HMAC-SHA512" $ do
      io "new" (DRBG512.new mempty mempty) mempty
      io "reseed" (DRBG512.reseed drbg512 mempty) mempty
      io "gen (32B)" (DRBG512.gen drbg512 mempty) 32
      io "gen (256B)" (DRBG512.gen drbg512 mempty) 256
