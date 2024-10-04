{-# OPTIONS_GHC -funbox-small-strict-fields #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}

-- |
-- Module: Crypto.DRBG.HMAC
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- A pure HMAC-DRBG implementation, as specified by
-- [NIST SP-800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf).

module Crypto.DRBG.HMAC (
    DRBG
  , _read_v
  , _read_k

  , new
  , gen
  , reseed
  ) where

import Control.Monad.Primitive (PrimMonad, PrimState)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Builder.Extra as BE
import qualified Data.Primitive.MutVar as P
import Data.Word (Word64)

-- keystroke savers and utilities ---------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

toStrict :: BSB.Builder -> BS.ByteString
toStrict = BS.toStrict . BSB.toLazyByteString
{-# INLINE toStrict #-}

toStrictSmall :: BSB.Builder -> BS.ByteString
toStrictSmall =
    BS.toStrict
  . BE.toLazyByteStringWith
      (BE.safeStrategy 128 BE.smallChunkSize) mempty
{-# INLINE toStrictSmall #-}

-- dumb strict pair
data Pair a b = Pair !a !b
  deriving Show

-- types ----------------------------------------------------------------------

-- see SP 800-90A table 2
_RESEED_COUNTER :: Word64
_RESEED_COUNTER = (2 :: Word64) ^ (48 :: Word64)

-- | A deterministic random bit generator (DRBG).
--
--   Create a DRBG with 'new', and then use and reuse it to generate
--   bytes as needed.
newtype DRBG s = DRBG (P.MutVar s DRBGState)

-- DRBG environment data and state
data DRBGState = DRBGState
                 !HMAC          -- hmac function & outlen
                 !Word64        -- reseed counter
  {-# UNPACK #-} !BS.ByteString -- v
  {-# UNPACK #-} !BS.ByteString -- key

-- HMAC function and its associated outlength
data HMAC = HMAC
                 !(BS.ByteString -> BS.ByteString -> BS.ByteString)
  {-# UNPACK #-} !Word64

-- Read the 'V' value from the DRBG state. Useful for testing.
_read_v
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m BS.ByteString
_read_v (DRBG mut) = do
  DRBGState _ _ v _ <- P.readMutVar mut
  pure v

-- Read the 'Key' value from the DRBG state. Useful for testing.
_read_k
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m BS.ByteString
_read_k (DRBG mut) = do
  DRBGState _ _ _ k <- P.readMutVar mut
  pure k

-- drbg interaction ------------------------------------------------------

-- | Create a DRBG from the supplied HMAC function, entropy, nonce, and
--   personalization string.
--
--   You can instantiate the DRBG using any appropriate HMAC function;
--   it should merely take a key and value as input, as is standard, and
--   return a MAC digest, each being a strict 'ByteString'.
--
--   The DRBG is returned in any 'PrimMonad', e.g. 'ST' or 'IO'.
--
--   >>> import qualified Crypto.Hash.SHA256 as SHA256
--   >>> new SHA256.hmac entropy nonce personalization_string
--   "<drbg>"
new
  :: PrimMonad m
  => (BS.ByteString -> BS.ByteString -> BS.ByteString) -- HMAC function
  -> BS.ByteString                                     -- entropy
  -> BS.ByteString                                     -- nonce
  -> BS.ByteString                                     -- personalization string
  -> m (DRBG (PrimState m))
new hmac entropy nonce ps = do
  let !drbg = new_pure hmac entropy nonce ps
  mut <- P.newMutVar drbg
  pure (DRBG mut)

-- | Reseed a DRBG.
--
--   Each DRBG has an internal /reseed counter/ that tracks the number
--   of requests made to the generator (note /requests made/, not /bytes
--   generated/). SP 800-90A specifies that a HMAC-DRBG should support
--   2 ^ 48 requests before requiring a reseed, so in practice you're
--   unlikely to ever need to use this to actually reset the counter.
--
--   Note however that 'reseed' can be used to implement "explicit"
--   prediction resistance, per SP 800-90A, by injecting entropy generated
--   elsewhere into the DRBG.
--
--   >>> import qualified System.Entropy as E
--   >>> entropy <- E.getEntropy 32
--   >>> reseed entropy addl_bytes drbg
--   "<reseeded drbg>"
reseed
  :: PrimMonad m
  => BS.ByteString
  -> BS.ByteString
  -> DRBG (PrimState m)
  -> m ()
reseed ent add (DRBG drbg) = P.modifyMutVar' drbg (reseed_pure ent add)

-- | Generate bytes from a DRBG, optionally injecting additional bytes
--   per SP 800-90A.
--
--   >>> import qualified Data.ByteString.Base16 as B16
--   >>> drbg <- new SHA256.hmac entropy nonce personalization_string
--   >>> bytes0 <- gen addl_bytes 16 drbg
--   >>> bytes1 <- gen addl_bytes 16 drbg
--   >>> B16.encode bytes0
--   "938d6ca6d0b797f7b3c653349d6e3135"
--   >>> B16.encode bytes1
--   "5f379d16de6f2c6f8a35c56f13f9e5a5"
gen
  :: PrimMonad m
  => BS.ByteString
  -> Word64
  -> DRBG (PrimState m)
  -> m BS.ByteString
gen addl bytes (DRBG mut) = do
  drbg0 <- P.readMutVar mut
  let !(Pair bs drbg1) = gen_pure addl bytes drbg0
  P.writeMutVar mut drbg1
  pure bs

-- pure drbg interaction ------------------------------------------------------

-- SP 800-90A 10.1.2.2
update_pure
  :: BS.ByteString
  -> DRBGState
  -> DRBGState
update_pure provided_data (DRBGState h@(HMAC hmac _) r v0 k0) =
    let !k1 = hmac k0 (cat v0 0x00 provided_data)
        !v1 = hmac k1 v0
    in  if   BS.null provided_data
        then DRBGState h r v1 k1
        else let !k2 = hmac k1 (cat v1 0x01 provided_data)
                 !v2 = hmac k2 v1
             in  DRBGState h r v2 k2
  where
    cat bs byte suf = toStrictSmall $
      BSB.byteString bs <> BSB.word8 byte <> BSB.byteString suf

-- SP 800-90A 10.1.2.3
new_pure
  :: (BS.ByteString -> BS.ByteString -> BS.ByteString) -- HMAC function
  -> BS.ByteString                                     -- entropy
  -> BS.ByteString                                     -- nonce
  -> BS.ByteString                                     -- personalization string
  -> DRBGState
new_pure hmac entropy nonce ps =
    let !drbg = DRBGState (HMAC hmac outlen) 1 v0 k0
    in  update_pure seed_material drbg
  where
    seed_material = entropy <> nonce <> ps
    outlen = fi (BS.length (hmac mempty mempty))
    k0 = BS.replicate (fi outlen) 0x00
    v0 = BS.replicate (fi outlen) 0x01

-- SP 800-90A 10.1.2.4
reseed_pure :: BS.ByteString -> BS.ByteString -> DRBGState -> DRBGState
reseed_pure entropy addl drbg =
  let !(DRBGState h _ v k) = update_pure (entropy <> addl) drbg
  in  DRBGState h 1 v k

-- SP 800-90A 10.1.2.5
gen_pure
  :: BS.ByteString
  -> Word64
  -> DRBGState
  -> Pair BS.ByteString DRBGState
gen_pure addl bytes drbg0@(DRBGState h@(HMAC hmac outlen) _ _ _)
    | r > _RESEED_COUNTER = error "ppad-sha256: reseed required"
    | otherwise =
        let !(Pair temp drbg1) = loop mempty 0 v1
            returned_bits = BS.take (fi bytes) temp
            drbg = update_pure addl drbg1
        in  Pair returned_bits drbg
  where
    !(DRBGState _ r v1 k1)
      | BS.null addl = drbg0
      | otherwise = update_pure addl drbg0

    loop !acc !len !vl
      | len < bytes =
          let nv   = hmac k1 vl
              nacc = acc <> BSB.byteString nv
              nlen = len + outlen
          in  loop nacc nlen nv

      | otherwise =
          let facc = toStrict acc
          in  Pair facc (DRBGState h (succ r) vl k1)

