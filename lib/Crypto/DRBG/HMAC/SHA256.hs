{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE UnboxedTuples #-}

-- |
-- Module: Crypto.DRBG.HMAC
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- A pure HMAC-DRBG implementation, as specified by
-- [NIST SP-800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf).

module Crypto.DRBG.HMAC.SHA256 (
  -- * DRBG and HMAC function types
    DRBG
  , Error(..)

  -- * DRBG interaction
  , new
  , gen
  , reseed
  , wipe

  -- for testing
  , _read_v
  , _read_k
  ) where

import Crypto.DRBG.HMAC.Internal (Error(..), _RESEED_COUNTER, _MAX_BYTES)
import qualified Crypto.Hash.SHA256 as SHA256
import Crypto.Hash.SHA256.Internal (Registers(..))
import qualified Crypto.Hash.SHA256.Internal as SHA256 (cat)
import Control.Monad.Primitive (PrimMonad, PrimState)
import qualified Control.Monad.Primitive as Prim (unsafeIOToPrim)
import Data.Bits ((.<<.), (.>>.), (.|.))
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Internal as BI
import qualified Data.Primitive.PrimArray as PA
import Data.Word (Word32, Word64)
import qualified GHC.Word
import qualified Foreign.Ptr as FP

-- api ------------------------------------------------------------------------

-- | A deterministic random bit generator (DRBG).
--
--   Create a DRBG with 'new', and then use and reuse it to generate
--   bytes as needed.
--
--   >>> drbg <- new entropy nonce personalization_string
--   >>> bytes0 <- gen drbg mempty 10
--   >>> bytes1 <- gen drbg mempty 10
--   >>> drbg
--   "<drbg>"

-- first two elements are hi/lo bits of word64 counter
-- next eight elements are k
-- next eight elements are v
-- next sixteen elements are scratch space
newtype DRBG s = DRBG (PA.MutablePrimArray s Word32)

instance Show (DRBG s) where
  show _ = "<drbg>"

-- | Create a HMAC-SHA256 DRBG from the supplied entropy, nonce, and
--   personalization string.
--
--   The DRBG is returned in any 'PrimMonad', e.g. 'ST s' or 'IO'.
--
--   >>> new entropy nonce personalization_string
--   "<drbg>"
new
  :: PrimMonad m
  => BS.ByteString    -- ^ entropy
  -> BS.ByteString    -- ^ nonce
  -> BS.ByteString    -- ^ personalization string
  -> m (DRBG (PrimState m))
new entropy nonce ps = do
  drbg <- PA.newPinnedPrimArray 34 -- 2 (ctr) + 16 (k, v) + 16 (scratch)
  init_counter drbg
  PA.setPrimArray drbg 02 08 (0x00000000 :: Word32) -- init k
  PA.setPrimArray drbg 10 08 (0x01010101 :: Word32) -- init v
  PA.setPrimArray drbg 18 16 (0x00000000 :: Word32) -- scratch
  update drbg (entropy <> nonce <> ps)
  pure $! DRBG drbg
{-# INLINABLE new #-}

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
  => DRBG (PrimState m)
  -> BS.ByteString
  -> BS.ByteString
  -> m ()
reseed (DRBG drbg) entr addl = do
  update drbg (entr <> addl)
  init_counter drbg
{-# INLINE reseed #-}

-- | Generate bytes from a DRBG, optionally injecting additional bytes
--   per SP 800-90A.
--
--   Per SP 800-90A, the maximum number of bytes that can be requested
--   on any invocation is 65536. Larger requests will return
--   'MaxBytesExceeded'.
--
--   >>> import qualified Data.ByteString.Base16 as B16
--   >>> drbg <- new entropy nonce personalization_string
--   >>> Right bytes0 <- gen drbg addl_bytes 16
--   >>> Right bytes1 <- gen drbg addl_bytes 16
--   >>> B16.encode bytes0
--   "938d6ca6d0b797f7b3c653349d6e3135"
--   >>> B16.encode bytes1
--   "5f379d16de6f2c6f8a35c56f13f9e5a5"
gen
  :: PrimMonad m
  => DRBG (PrimState m)
  -> BS.ByteString
  -> Word64
  -> m (Either Error BS.ByteString)
gen (DRBG drbg) addl@(BI.PS _ _ l) bytes
  | bytes > _MAX_BYTES = pure $! Left MaxBytesExceeded
  | otherwise = do
      ctr <- read_counter drbg
      if   ctr > _RESEED_COUNTER
      then pure $! Left ReseedRequired
      else do
        if l == 0 then pure () else update drbg addl
        !(GHC.Word.W32# k00) <- PA.readPrimArray drbg 02
        !(GHC.Word.W32# k01) <- PA.readPrimArray drbg 03
        !(GHC.Word.W32# k02) <- PA.readPrimArray drbg 04
        !(GHC.Word.W32# k03) <- PA.readPrimArray drbg 05
        !(GHC.Word.W32# k04) <- PA.readPrimArray drbg 06
        !(GHC.Word.W32# k05) <- PA.readPrimArray drbg 07
        !(GHC.Word.W32# k06) <- PA.readPrimArray drbg 08
        !(GHC.Word.W32# k07) <- PA.readPrimArray drbg 09
        !(GHC.Word.W32# v00) <- PA.readPrimArray drbg 10
        !(GHC.Word.W32# v01) <- PA.readPrimArray drbg 11
        !(GHC.Word.W32# v02) <- PA.readPrimArray drbg 12
        !(GHC.Word.W32# v03) <- PA.readPrimArray drbg 13
        !(GHC.Word.W32# v04) <- PA.readPrimArray drbg 14
        !(GHC.Word.W32# v05) <- PA.readPrimArray drbg 15
        !(GHC.Word.W32# v06) <- PA.readPrimArray drbg 16
        !(GHC.Word.W32# v07) <- PA.readPrimArray drbg 17
        let !k0  = Registers (# k00, k01, k02, k03, k04, k05, k06, k07 #)
            !v0  = Registers (# v00, v01, v02, v03, v04, v05, v06, v07 #)
        !res <- gen_loop drbg k0 v0 bytes
        update drbg addl
        write_counter drbg (ctr + 1)
        pure $! Right res
{-# INLINABLE gen #-}

-- | Wipe the state of a DRBG.
--
--   You should call this when you're finished with a DRBG to ensure that its
--   state is wiped from memory.
--
--   >>> drbg <- new mempty mempty mempty
--   >>> Right bytes <- gen drbg addl_bytes 16
--   >>> wipe drbg
--   >>> -- do something with bytes
wipe
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m ()
wipe (DRBG drbg) = do
  init_counter drbg
  PA.setPrimArray drbg 02 08 (0x00000000 :: Word32) -- init k
  PA.setPrimArray drbg 10 08 (0x01010101 :: Word32) -- init v
  PA.setPrimArray drbg 18 16 (0x00000000 :: Word32) -- init scratch
{-# INLINE wipe #-}
-- utilities ------------------------------------------------------------------

fi :: (Integral a, Num b) => a -> b
fi = fromIntegral
{-# INLINE fi #-}

-- drbg utilities -------------------------------------------------------------

gen_loop
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word32
  -> Registers
  -> Registers
  -> Word64
  -> m BS.ByteString
gen_loop drbg k0 v0 bytes = loop mempty v0 0 where
  !vp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 40 -- 10 * 4
  !sp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 72 -- 18 * 4
  loop !acc v l
    | l >= bytes = do
        write_v drbg v
        pure acc
    | otherwise = do
        Prim.unsafeIOToPrim $ SHA256._hmac_rr vp sp k0 v
        !(GHC.Word.W32# nv0) <- PA.readPrimArray drbg 10
        !(GHC.Word.W32# nv1) <- PA.readPrimArray drbg 11
        !(GHC.Word.W32# nv2) <- PA.readPrimArray drbg 12
        !(GHC.Word.W32# nv3) <- PA.readPrimArray drbg 13
        !(GHC.Word.W32# nv4) <- PA.readPrimArray drbg 14
        !(GHC.Word.W32# nv5) <- PA.readPrimArray drbg 15
        !(GHC.Word.W32# nv6) <- PA.readPrimArray drbg 16
        !(GHC.Word.W32# nv7) <- PA.readPrimArray drbg 17
        let !nv = Registers (# nv0, nv1, nv2, nv3, nv4, nv5, nv6, nv7 #)
            !na = acc <> SHA256.cat nv
            !nl = l + 32
        loop na nv nl
{-# INLINE gen_loop #-}

update
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word32
  -> BS.ByteString
  -> m ()
update drbg provided_data@(BI.PS _ _ l) = do
  !(GHC.Word.W32# k00) <- PA.readPrimArray drbg 02
  !(GHC.Word.W32# k01) <- PA.readPrimArray drbg 03
  !(GHC.Word.W32# k02) <- PA.readPrimArray drbg 04
  !(GHC.Word.W32# k03) <- PA.readPrimArray drbg 05
  !(GHC.Word.W32# k04) <- PA.readPrimArray drbg 06
  !(GHC.Word.W32# k05) <- PA.readPrimArray drbg 07
  !(GHC.Word.W32# k06) <- PA.readPrimArray drbg 08
  !(GHC.Word.W32# k07) <- PA.readPrimArray drbg 09
  !(GHC.Word.W32# v00) <- PA.readPrimArray drbg 10
  !(GHC.Word.W32# v01) <- PA.readPrimArray drbg 11
  !(GHC.Word.W32# v02) <- PA.readPrimArray drbg 12
  !(GHC.Word.W32# v03) <- PA.readPrimArray drbg 13
  !(GHC.Word.W32# v04) <- PA.readPrimArray drbg 14
  !(GHC.Word.W32# v05) <- PA.readPrimArray drbg 15
  !(GHC.Word.W32# v06) <- PA.readPrimArray drbg 16
  !(GHC.Word.W32# v07) <- PA.readPrimArray drbg 17
  let !k0 = Registers (# k00, k01, k02, k03, k04, k05, k06, k07 #)
      !v0 = Registers (# v00, v01, v02, v03, v04, v05, v06, v07 #)
      !kp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 08 --  2 * 4
      !vp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 40 -- 10 * 4
      !sp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 72 -- 18 * 4
  Prim.unsafeIOToPrim $ SHA256._hmac_rsb kp sp k0 v0 0x00 provided_data
  !(GHC.Word.W32# k10) <- PA.readPrimArray drbg 02
  !(GHC.Word.W32# k11) <- PA.readPrimArray drbg 03
  !(GHC.Word.W32# k12) <- PA.readPrimArray drbg 04
  !(GHC.Word.W32# k13) <- PA.readPrimArray drbg 05
  !(GHC.Word.W32# k14) <- PA.readPrimArray drbg 06
  !(GHC.Word.W32# k15) <- PA.readPrimArray drbg 07
  !(GHC.Word.W32# k16) <- PA.readPrimArray drbg 08
  !(GHC.Word.W32# k17) <- PA.readPrimArray drbg 09
  let !k1 = Registers (# k10, k11, k12, k13, k14, k15, k16, k17 #)
  Prim.unsafeIOToPrim $ SHA256._hmac_rr vp sp k1 v0
  if   l == 0
  then pure ()
  else do
    !(GHC.Word.W32# v10) <- PA.readPrimArray drbg 10
    !(GHC.Word.W32# v11) <- PA.readPrimArray drbg 11
    !(GHC.Word.W32# v12) <- PA.readPrimArray drbg 12
    !(GHC.Word.W32# v13) <- PA.readPrimArray drbg 13
    !(GHC.Word.W32# v14) <- PA.readPrimArray drbg 14
    !(GHC.Word.W32# v15) <- PA.readPrimArray drbg 15
    !(GHC.Word.W32# v16) <- PA.readPrimArray drbg 16
    !(GHC.Word.W32# v17) <- PA.readPrimArray drbg 17
    let !v1 = Registers (# v10, v11, v12, v13, v14, v15, v16, v17 #)
    Prim.unsafeIOToPrim $ SHA256._hmac_rsb kp sp k1 v1 0x01 provided_data
    !(GHC.Word.W32# k20) <- PA.readPrimArray drbg 02
    !(GHC.Word.W32# k21) <- PA.readPrimArray drbg 03
    !(GHC.Word.W32# k22) <- PA.readPrimArray drbg 04
    !(GHC.Word.W32# k23) <- PA.readPrimArray drbg 05
    !(GHC.Word.W32# k24) <- PA.readPrimArray drbg 06
    !(GHC.Word.W32# k25) <- PA.readPrimArray drbg 07
    !(GHC.Word.W32# k26) <- PA.readPrimArray drbg 08
    !(GHC.Word.W32# k27) <- PA.readPrimArray drbg 09
    let !k2 = Registers (# k20, k21, k22, k23, k24, k25, k26, k27 #)
    Prim.unsafeIOToPrim $ SHA256._hmac_rr vp sp k2 v1
{-# INLINABLE update #-}

init_counter
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word32
  -> m ()
init_counter drbg = do
  PA.writePrimArray drbg 0 (0x00 :: Word32) -- init high word, counter
  PA.writePrimArray drbg 1 (0x01 :: Word32) -- init low word, counter
{-# INLINE init_counter #-}

read_counter
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word32
  -> m Word64
read_counter drbg = do
  !hi <- PA.readPrimArray drbg 0
  !lo <- PA.readPrimArray drbg 1
  let !ctr = fi hi .<<. 32 .|. fi lo
  pure $! ctr
{-# INLINE read_counter #-}

write_counter
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word32
  -> Word64
  -> m ()
write_counter drbg ctr = do
  let !hi = fi (ctr .>>. 32)
      !lo = fi ctr
  PA.writePrimArray drbg 0 hi
  PA.writePrimArray drbg 1 lo
{-# INLINE write_counter #-}

write_v
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word32
  -> Registers
  -> m ()
write_v drbg (R v0 v1 v2 v3 v4 v5 v6 v7) = do
  PA.writePrimArray drbg 10 (GHC.Word.W32# v0)
  PA.writePrimArray drbg 11 (GHC.Word.W32# v1)
  PA.writePrimArray drbg 12 (GHC.Word.W32# v2)
  PA.writePrimArray drbg 13 (GHC.Word.W32# v3)
  PA.writePrimArray drbg 14 (GHC.Word.W32# v4)
  PA.writePrimArray drbg 15 (GHC.Word.W32# v5)
  PA.writePrimArray drbg 16 (GHC.Word.W32# v6)
  PA.writePrimArray drbg 17 (GHC.Word.W32# v7)
{-# INLINE write_v #-}

-- read secret drbg state (for testing)
_read_v
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m BS.ByteString
_read_v (DRBG drbg) = do
  !v00 <- PA.readPrimArray drbg 10
  !v01 <- PA.readPrimArray drbg 11
  !v02 <- PA.readPrimArray drbg 12
  !v03 <- PA.readPrimArray drbg 13
  !v04 <- PA.readPrimArray drbg 14
  !v05 <- PA.readPrimArray drbg 15
  !v06 <- PA.readPrimArray drbg 16
  !v07 <- PA.readPrimArray drbg 17
  pure . BS.toStrict . BSB.toLazyByteString $ mconcat [
      BSB.word32BE v00
    , BSB.word32BE v01
    , BSB.word32BE v02
    , BSB.word32BE v03
    , BSB.word32BE v04
    , BSB.word32BE v05
    , BSB.word32BE v06
    , BSB.word32BE v07
    ]

-- read secret drbg state (for testing)
_read_k
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m BS.ByteString
_read_k (DRBG drbg) = do
  !k00 <- PA.readPrimArray drbg 02
  !k01 <- PA.readPrimArray drbg 03
  !k02 <- PA.readPrimArray drbg 04
  !k03 <- PA.readPrimArray drbg 05
  !k04 <- PA.readPrimArray drbg 06
  !k05 <- PA.readPrimArray drbg 07
  !k06 <- PA.readPrimArray drbg 08
  !k07 <- PA.readPrimArray drbg 09
  pure . BS.toStrict . BSB.toLazyByteString $ mconcat [
      BSB.word32BE k00
    , BSB.word32BE k01
    , BSB.word32BE k02
    , BSB.word32BE k03
    , BSB.word32BE k04
    , BSB.word32BE k05
    , BSB.word32BE k06
    , BSB.word32BE k07
    ]

