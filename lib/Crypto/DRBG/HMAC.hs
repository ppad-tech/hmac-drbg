{-# OPTIONS_GHC -funbox-small-strict-fields #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}

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
import qualified Data.Primitive.MutVar as P
import Data.Word (Word64)

-- keystroke savers and utilities ---------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

toStrict :: BSB.Builder -> BS.ByteString
toStrict = BS.toStrict . BSB.toLazyByteString
{-# INLINE toStrict #-}

-- dumb strict pair
data Pair a b = Pair !a !b
  deriving Show

-- types ----------------------------------------------------------------------

-- HMAC function and its associated outlength
data HMAC = HMAC
                 !(BS.ByteString -> BS.ByteString -> BS.ByteString)
  {-# UNPACK #-} !Word64

-- DRBG environment data and state
--
-- XX probably track, handle the reseed counter again; there's also security
--    strength, length input verification, etc.
data DRBGState = DRBGState
                 !HMAC          -- hmac function & outlen
  {-# UNPACK #-} !BS.ByteString -- v
  {-# UNPACK #-} !BS.ByteString -- key

-- | The DRBG.
newtype DRBG s = DRBG (P.MutVar s DRBGState)

-- | Read the 'V' value from the DRBG state. Useful for testing.
_read_v
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m BS.ByteString
_read_v (DRBG mut) = do
  DRBGState _ v _ <- P.readMutVar mut
  pure v

-- | Read the 'Key' value from the DRBG state. Useful for testing.
_read_k
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m BS.ByteString
_read_k (DRBG mut) = do
  DRBGState _ _ k <- P.readMutVar mut
  pure k

-- drbg interaction ------------------------------------------------------

-- | Create a DRBG from the supplied HMAC function, entropy, nonce, and
--   personalization string.
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
--   Note that this can be used to implement "explicit" permission
--   resistance by injecting entropy generated elsewhere.
reseed
  :: PrimMonad m
  => BS.ByteString
  -> BS.ByteString
  -> DRBG (PrimState m)
  -> m ()
reseed ent add (DRBG drbg) = P.modifyMutVar' drbg (reseed_pure ent add)

-- | Generate bytes from a DRBG.
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

update_pure
  :: BS.ByteString
  -> DRBGState
  -> DRBGState
update_pure provided_data (DRBGState h@(HMAC hmac _) v0 k0) =
    let !k1 = hmac k0 (cat v0 0x00 provided_data)
        !v1 = hmac k1 v0
    in  if   BS.null provided_data
        then (DRBGState h v1 k1)
        else let !k2 = hmac k1 (cat v1 0x01 provided_data)
                 !v2 = hmac k2 v1
             in  DRBGState h v2 k2
  where
    -- XX custom builder strategy possibly more efficient here
    cat bs byte suf = toStrict $
      BSB.byteString bs <> BSB.word8 byte <> BSB.byteString suf

new_pure
  :: (BS.ByteString -> BS.ByteString -> BS.ByteString) -- HMAC function
  -> BS.ByteString                                     -- entropy
  -> BS.ByteString                                     -- nonce
  -> BS.ByteString                                     -- personalization string
  -> DRBGState
new_pure hmac entropy nonce ps =
    let !drbg = DRBGState (HMAC hmac outlen) v0 k0
    in  update_pure seed_material drbg
  where
    -- XX any better to use builder?
    seed_material = entropy <> nonce <> ps
    outlen = fi (BS.length (hmac mempty mempty))
    k0 = BS.replicate (fi outlen) 0x00
    v0 = BS.replicate (fi outlen) 0x01

reseed_pure :: BS.ByteString -> BS.ByteString -> DRBGState -> DRBGState
reseed_pure entropy addl drbg = update_pure (entropy <> addl) drbg

gen_pure
  :: BS.ByteString
  -> Word64
  -> DRBGState
  -> Pair BS.ByteString DRBGState
gen_pure addl bytes drbg0@(DRBGState h@(HMAC hmac outlen) _ _) =
    let !(Pair temp drbg1) = loop mempty 0 v1
        returned_bits = BS.take (fi bytes) temp
        drbg = update_pure addl drbg1
    in  Pair returned_bits drbg
  where
    !(DRBGState _ v1 k1)
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
          in  Pair facc (DRBGState h vl k1)

