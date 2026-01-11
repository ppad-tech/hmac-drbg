{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

-- NOTE: weigh forks a subprocess per test, so each test pays ~32KB of
-- process initialization overhead. Direct measurement via GHC.Stats
-- shows actual per-call allocation is ~1.1KB for DRBG.new.

module Main where

import Control.DeepSeq
import qualified Crypto.DRBG.HMAC.SHA256 as DRBG
import Weigh

instance NFData (DRBG.DRBG s) where
  rnf d = d `seq` ()

instance NFData DRBG.Error where
  rnf e = e `seq` ()

main :: IO ()
main = do
  !drbg <- DRBG.new mempty mempty mempty
  mainWith $ do
    wgroup "HMAC-SHA256" $ do
      io "new" (DRBG.new mempty mempty) mempty
      io "reseed" (DRBG.reseed drbg mempty) mempty
      io "gen (32B)" (DRBG.gen drbg mempty) 32
      io "gen (256B)" (DRBG.gen drbg mempty) 256
