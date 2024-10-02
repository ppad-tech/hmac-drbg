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

import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import Data.Word (Word64)

import Control.Monad.Primitive (PrimMonad, PrimState)
import qualified Data.Primitive.MutVar as P

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
data DRBG = DRBG
                 !HMAC          -- hmac function & outlen
  {-# UNPACK #-} !BS.ByteString -- v
  {-# UNPACK #-} !BS.ByteString -- key

-- | Read the 'V' value from the DRBG state.
_read_v :: DRBG -> BS.ByteString
_read_v (DRBG _ v _) = v

-- | Read the 'Key' value from the DRBG state.
_read_k :: DRBG -> BS.ByteString
_read_k (DRBG _ _ key) = key

-- | Primitive formulation.
newtype Gen s = Gen (P.MutVar s DRBG)

-- drbg interaction -----------------------------------------------------------

update_pure
  :: BS.ByteString
  -> DRBG
  -> DRBG
update_pure provided_data (DRBG h@(HMAC hmac _) v0 k0) =
    let !k1 = hmac k0 (cat v0 0x00 provided_data)
        !v1 = hmac k1 v0
    in  if   BS.null provided_data
        then (DRBG h v1 k1)
        else let !k2 = hmac k1 (cat v1 0x01 provided_data)
                 !v2 = hmac k2 v1
             in  DRBG h v2 k2
  where
    cat bs byte suf = toStrict $
      BSB.byteString bs <> BSB.word8 byte <> BSB.byteString suf

update_prim
  :: PrimMonad m
  => BS.ByteString
  -> Gen (PrimState m)
  -> m ()
update_prim pd (Gen gen) = P.modifyMutVar' gen (update_pure pd)

-- | Create a DRBG from the provided HMAC function, entropy, nonce, and
--   personalization string.
new_pure
  :: (BS.ByteString -> BS.ByteString -> BS.ByteString) -- HMAC function
  -> BS.ByteString                                     -- entropy
  -> BS.ByteString                                     -- nonce
  -> BS.ByteString                                     -- personalization string
  -> DRBG
new_pure hmac entropy nonce ps =
    let !drbg = DRBG (HMAC hmac outlen) v0 k0
    in  update_pure seed_material drbg
  where
    seed_material = entropy <> nonce <> ps
    outlen = fi (BS.length (hmac mempty mempty))
    k0 = BS.replicate (fi outlen) 0x00
    v0 = BS.replicate (fi outlen) 0x01

new_prim
  :: PrimMonad m
  => (BS.ByteString -> BS.ByteString -> BS.ByteString) -- HMAC function
  -> BS.ByteString                                     -- entropy
  -> BS.ByteString                                     -- nonce
  -> BS.ByteString                                     -- personalization string
  -> m (Gen (PrimState m))
new_prim hmac entropy nonce ps = do
  let !drbg = new_pure hmac entropy nonce ps
  mut <- P.newMutVar drbg
  pure (Gen mut)

-- | Inject entropy and additional bytes into a DRBG.
--
--   Note that we don't support "proper" reseeding (i.e., we don't track
--   a reseed counter), but this can be used for injecting entropy per
--   spec.
reseed_pure :: BS.ByteString -> BS.ByteString -> DRBG -> DRBG
reseed_pure entropy addl drbg = update_pure (entropy <> addl) drbg

reseed_prim
  :: PrimMonad m
  => BS.ByteString
  -> BS.ByteString
  -> Gen (PrimState m)
  -> m ()
reseed_prim ent add (Gen gen) = P.modifyMutVar' gen (reseed_pure ent add)

gen_pure
  :: BS.ByteString
  -> Word64
  -> DRBG
  -> (BS.ByteString, DRBG)
gen_pure addl bytes drbg0@(DRBG h@(HMAC hmac outlen) _ _) =
    let !(Pair temp drbg1) = loop mempty 0 v1
        !returned_bits = BS.take (fi bytes) temp
        !drbg = update_pure addl drbg1
    in  (returned_bits, drbg) -- XX this could use a strict pair
  where
    !(DRBG _ v1 k1)
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
          in  Pair facc (DRBG h vl k1)

gen_prim
  :: PrimMonad m
  => BS.ByteString
  -> Word64
  -> Gen (PrimState m)
  -> m BS.ByteString
gen_prim addl bytes (Gen mut) = do
  drbg0 <- P.readMutVar mut
  let !(bs, !drbg1) = gen_pure addl bytes drbg0
  P.writeMutVar mut drbg1
  pure $! bs

