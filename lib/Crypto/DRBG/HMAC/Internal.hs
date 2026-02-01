{-# OPTIONS_HADDOCK hide #-}

-- |
-- Module: Crypto.DRBG.HMAC.Internal
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- Internal HMAC-DRBG definitions.

module Crypto.DRBG.HMAC.Internal (
    Error(..)
  , _RESEED_COUNTER
  , _MAX_BYTES
  ) where

import Data.Word (Word64)

-- | A DRBG error.
data Error =
    MaxBytesExceeded -- ^ More than 65536 bytes have been requested.
  | ReseedRequired   -- ^ The DRBG must be reseeded (via 'reseed').
  deriving (Eq, Show)

-- see SP 800-90A table 2
_RESEED_COUNTER :: Word64
_RESEED_COUNTER = (2 :: Word64) ^ (48 :: Word64)
{-# INLINE _RESEED_COUNTER #-}

-- see SP 800-90A table 2
_MAX_BYTES :: Word64
_MAX_BYTES = 0x10000
{-# INLINE _MAX_BYTES #-}
