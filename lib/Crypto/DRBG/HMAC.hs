{-# OPTIONS_HADDOCK prune #-}
{-# OPTIONS_GHC -funbox-small-strict-fields #-}
{-# LANGUAGE BangPatterns #-}

-- |
-- Module: Crypto.DRBG.HMAC
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- A pure HMAC-DRBG implementation, as specified by
-- [NIST SP-800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf).

module Crypto.DRBG.HMAC (
  -- * DRBG and HMAC function types
    DRBG
  , _read_v
  , _read_k
  , HMAC

  -- * DRBG interaction
  , new
  , gen
  , reseed
  ) where

import Control.Monad.Primitive (PrimMonad, PrimState)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Builder.Extra as BE
import qualified Data.ByteString.Internal as BI
import qualified Data.Primitive.MutVar as P
import Data.Word (Word64)

-- keystroke savers and utilities ---------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

to_strict :: BSB.Builder -> BS.ByteString
to_strict = BS.toStrict . BSB.toLazyByteString
{-# INLINE to_strict #-}

to_strict_small :: BSB.Builder -> BS.ByteString
to_strict_small = BS.toStrict . BE.toLazyByteStringWith
  (BE.safeStrategy 128 BE.smallChunkSize) mempty
{-# INLINE to_strict_small #-}

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
--
--   >>> import qualified Crypto.Hash.SHA256 as SHA256
--   >>> drbg <- new SHA256.hmac entropy nonce personalization_string
--   >>> bytes0 <- gen addl_bytes 16 drbg
--   >>> bytes1 <- gen addl_bytes 16 drbg
--   >>> drbg
--   "<drbg>"
newtype DRBG s = DRBG (P.MutVar s DRBGState)

instance Show (DRBG s) where
  show _ = "<drbg>"

-- DRBG environment data and state
data DRBGState = DRBGState
                 !HMACEnv       -- hmac function & outlen
  {-# UNPACK #-} !Word64        -- reseed counter
  {-# UNPACK #-} !BS.ByteString -- v
  {-# UNPACK #-} !BS.ByteString -- key

-- NB following synonym really only exists to make haddocks more
--    readable

-- | A HMAC function, taking a key as the first argument and the input
--   value as the second, producing a MAC digest.
--
--   >>> import qualified Crypto.Hash.SHA256 as SHA256
--   >>> :t SHA256.hmac
--   SHA256.hmac :: BS.ByteString -> BS.ByteString -> BS.ByteString
type HMAC = BS.ByteString -> BS.ByteString -> BS.ByteString

-- HMAC function and its associated outlength
data HMACEnv = HMACEnv
                 !HMAC
  {-# UNPACK #-} !Word64

-- the following convenience functions are useful for testing

_read_v
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m BS.ByteString
_read_v (DRBG mut) = do
  DRBGState _ _ v _ <- P.readMutVar mut
  pure v

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
  => HMAC           -- ^ HMAC function
  -> BS.ByteString  -- ^ entropy
  -> BS.ByteString  -- ^ nonce
  -> BS.ByteString  -- ^ personalization string
  -> m (DRBG (PrimState m))
new hmac entropy nonce ps = do
  let !drbg = new_pure hmac entropy nonce ps
  mut <- P.newMutVar drbg
  pure (DRBG mut)

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
  => BS.ByteString       -- ^ additional bytes to inject
  -> Word64              -- ^ number of bytes to generate
  -> DRBG (PrimState m)
  -> m BS.ByteString
gen addl bytes (DRBG mut) = do
  drbg0 <- P.readMutVar mut
  let !(Pair bs drbg1) = gen_pure addl bytes drbg0
  P.writeMutVar mut drbg1
  pure bs

-- | Reseed a DRBG.
--
--   Each DRBG has an internal /reseed counter/ that tracks the number
--   of requests made to the generator (note /requests made/, not bytes
--   generated). SP 800-90A specifies that a HMAC-DRBG should support
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
  => BS.ByteString        -- ^ entropy to inject
  -> BS.ByteString        -- ^ additional bytes to inject
  -> DRBG (PrimState m)
  -> m ()
reseed ent add (DRBG drbg) = P.modifyMutVar' drbg (reseed_pure ent add)

-- pure drbg interaction ------------------------------------------------------

-- SP 800-90A 10.1.2.2
update_pure
  :: BS.ByteString
  -> DRBGState
  -> DRBGState
update_pure provided_data (DRBGState h@(HMACEnv hmac _) r v0 k0) =
    let !k1 = hmac k0 (cat v0 0x00 provided_data)
        !v1 = hmac k1 v0
    in  if   BS.null provided_data
        then DRBGState h r v1 k1
        else let !k2 = hmac k1 (cat v1 0x01 provided_data)
                 !v2 = hmac k2 v1
             in  DRBGState h r v2 k2
  where
    cat bs byte suf@(BI.PS _ _ l) =
      let bil = BSB.byteString bs <> BSB.word8 byte <> BSB.byteString suf
      in  if   l < 64
          then to_strict_small bil
          else to_strict bil
    {-# INLINE cat #-}

-- SP 800-90A 10.1.2.3
new_pure
  :: HMAC           -- HMAC function
  -> BS.ByteString  -- entropy
  -> BS.ByteString  -- nonce
  -> BS.ByteString  -- personalization string
  -> DRBGState
new_pure hmac entropy nonce ps =
    let !drbg = DRBGState (HMACEnv hmac outlen) 1 v0 k0
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
gen_pure addl bytes drbg0@(DRBGState h@(HMACEnv hmac outlen) _ _ _)
    | r > _RESEED_COUNTER = error "ppad-hmac-drbg: reseed required"
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
          let facc | bytes < 128 = to_strict_small acc
                   | otherwise   = to_strict acc
          in  Pair facc (DRBGState h (succ r) vl k1)
{-# INLINE gen_pure #-}

