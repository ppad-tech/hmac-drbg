{-# OPTIONS_GHC -funbox-small-strict-fields #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}

module Crypto.DRBG.HMAC (
    DRBG
  , read_v
  , read_key

  , new
  , gen
  , reseed
  ) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
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
data DRBG = DRBG
                 !HMAC          -- hmac function & outlen
  {-# UNPACK #-} !BS.ByteString -- v
  {-# UNPACK #-} !BS.ByteString -- key

-- | Read the 'V' value from the DRBG state.
read_v :: DRBG -> BS.ByteString
read_v (DRBG _ v _) = v

-- | Read the 'Key' value from the DRBG state.
read_key :: DRBG -> BS.ByteString
read_key (DRBG _ _ key) = key

-- drbg interaction -----------------------------------------------------------

update
  :: BS.ByteString
  -> DRBG
  -> DRBG
update provided_data (DRBG h@(HMAC hmac _) v0 k0) =
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

-- | Create a DRBG from the provided HMAC function, entropy, nonce, and
--   personalization string.
new
  :: (BS.ByteString -> BS.ByteString -> BS.ByteString) -- HMAC function
  -> BS.ByteString                                     -- entropy
  -> BS.ByteString                                     -- nonce
  -> BS.ByteString                                     -- personalization string
  -> DRBG
new hmac entropy nonce ps =
    let !drbg = DRBG (HMAC hmac outlen) v0 k0
    in  update seed_material drbg
  where
    seed_material = entropy <> nonce <> ps
    outlen = fi (BS.length (hmac mempty mempty))
    k0 = BS.replicate (fi outlen) 0x00
    v0 = BS.replicate (fi outlen) 0x01

-- | Inject entropy and additional bytes into a DRBG.
--
--   Note that we don't support "proper" reseeding (i.e., we don't track
--   a reseed counter), but this can be used for injecting entropy per
--   spec.
reseed :: BS.ByteString -> BS.ByteString -> DRBG -> DRBG
reseed entropy addl drbg = update (entropy <> addl) drbg

gen
  :: BS.ByteString
  -> Word64
  -> DRBG
  -> (BS.ByteString, DRBG)
gen addl bytes drbg0@(DRBG h@(HMAC hmac outlen) _ _) =
    let !(Pair temp drbg1) = loop mempty 0 v1
        !returned_bits = BS.take (fi bytes) temp
        !drbg = update addl drbg1
    in  (returned_bits, drbg)
  where
    !(DRBG _ v1 k1)
      | BS.null addl = drbg0
      | otherwise = update addl drbg0

    loop !acc !len !vl
      | len < bytes =
          let nv   = hmac k1 vl
              nacc = acc <> BSB.byteString nv
              nlen = len + outlen
          in  loop nacc nlen nv

      | otherwise =
          let facc = toStrict acc
          in  Pair facc (DRBG h vl k1)

