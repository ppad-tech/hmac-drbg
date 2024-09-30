{-# OPTIONS_GHC -funbox-small-strict-fields #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE LambdaCase #-}

module Crypto.DRBG.HMAC where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import Data.Word (Word64)

-- keystroke saver
fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

_RESEED_INTERVAL :: Word64
_RESEED_INTERVAL = (2 :: Word64) ^ (48 :: Word64)

data HMAC = HMAC
  !(BS.ByteString -> BS.ByteString -> BS.ByteString)
  {-# UNPACK #-} !Word64

data DRBG = DRBG
                 !HMAC              -- hmac function & outlen
  {-# UNPACK #-} !BS.ByteString     -- v
  {-# UNPACK #-} !BS.ByteString     -- key
  {-# UNPACK #-} !Word64            -- reseed_counter

instance Show DRBG where
  show (DRBG _ v k r) = "DRBG " <> show v <> " " <> show k <> " " <> show r

-- dumb strict pair
data Pair a b = Pair !a !b
  deriving Show

update
  :: BS.ByteString
  -> DRBG
  -> DRBG
update provided_data (DRBG h@(HMAC hmac _) v0 k0 r) =
    let !k1 = hmac k0 (suf 0x00 v0)
        !v1 = hmac k1 v0
    in  if   BS.null provided_data
        then (DRBG h v1 k1 r)
        else let !k2 = hmac k1 (suf 0x01 v1)
                 !v2 = hmac k2 v1
             in  DRBG h v2 k2 r
  where
    suf byte bs = BS.toStrict
      . BSB.toLazyByteString
      $ BSB.byteString bs <> BSB.word8 byte <> BSB.byteString provided_data

instantiate
  :: (BS.ByteString -> BS.ByteString -> BS.ByteString)
  -> BS.ByteString
  -> BS.ByteString
  -> BS.ByteString
  -> DRBG
instantiate hmac entropy nonce ps =
    let drbg = DRBG (HMAC hmac outlen) v0 k0 1
    in  update seed_material drbg
  where
    seed_material = entropy <> nonce <> ps
    outlen = fi (BS.length (hmac mempty mempty)) -- UX hack, costs 1 hmac call
    k0 = BS.replicate (fi outlen) 0x00
    v0 = BS.replicate (fi outlen) 0x01

reseed :: DRBG -> BS.ByteString -> BS.ByteString -> DRBG
reseed drbg entropy addl =
    let !(DRBG hmac v k _) = update seed_material drbg
    in  DRBG hmac v k 1
  where
    seed_material = entropy <> addl

generate
  :: BS.ByteString
  -> Word64
  -> DRBG
  -> (BS.ByteString, DRBG)
generate addl bytes drbg0@(DRBG h@(HMAC hmac outlen) _ _ r)
    | r > _RESEED_INTERVAL = error "ppad-hmac-drbg: DRBG reseed required"
    | otherwise =
        let !(Pair temp drbg1) = go mempty 0 v1

            !returned_bits = BS.take (fi bytes) temp
            !drbg2 = update addl drbg1

        in  (returned_bits, drbg2)
  where
    !(DRBG _ v1 k1 _)
      | BS.null addl = drbg0
      | otherwise = update addl drbg0

    go !acc !len !vl
      | len < bytes =
          let nv   = hmac k1 vl
              nacc = acc <> BSB.byteString nv
              nlen = len + outlen
          in  go nacc nlen nv

      -- take opportunity to update reseed_counter here
      | otherwise =
          let facc = BS.toStrict . BSB.toLazyByteString $ acc
          in  Pair facc (DRBG h vl k1 (succ r))


-- XX test against
-- https://raw.githubusercontent.com/coruus/nist-testvectors/refs/heads/master/csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors/drbgvectors_pr_true/HMAC_DRBG.txt
