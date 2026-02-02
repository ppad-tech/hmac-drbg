{-# OPTIONS_HADDOCK prune #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE UnboxedTuples #-}

-- |
-- Module: Crypto.DRBG.HMAC.SHA512
-- Copyright: (c) 2024 Jared Tobin
-- License: MIT
-- Maintainer: Jared Tobin <jared@ppad.tech>
--
-- A pure HMAC-DRBG implementation, as specified by
-- [NIST SP-800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf).

module Crypto.DRBG.HMAC.SHA512 (
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
import qualified Crypto.Hash.SHA512 as SHA512
import Crypto.Hash.SHA512.Internal (Registers(..))
import qualified Crypto.Hash.SHA512.Internal as SHA512 (cat)
import Control.Monad.Primitive (PrimMonad, PrimState)
import Control.Monad.ST (ST)
import GHC.Exts (RealWorld)
import qualified Control.Monad.Primitive as Prim (unsafeIOToPrim)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BSB
import qualified Data.ByteString.Internal as BI
import qualified Data.Primitive.PrimArray as PA
import Data.Word (Word64)
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

-- layout (Word64 array):
-- index 0: counter
-- indices 1-8: k (8 Word64s = 64 bytes)
-- indices 9-16: v (8 Word64s = 64 bytes)
-- indices 17-32: scratch space (16 Word64s = 128 bytes)
newtype DRBG s = DRBG (PA.MutablePrimArray s Word64)

instance Show (DRBG s) where
  show _ = "<drbg>"

-- | Create a HMAC-SHA512 DRBG from the supplied entropy, nonce, and
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
  drbg <- PA.newPinnedPrimArray 33 -- 1 (ctr) + 16 (k, v) + 16 (scratch)
  init_counter drbg
  PA.setPrimArray drbg 01 08 (0x0000000000000000 :: Word64) -- init k
  PA.setPrimArray drbg 09 08 (0x0101010101010101 :: Word64) -- init v
  PA.setPrimArray drbg 17 16 (0x0000000000000000 :: Word64) -- scratch
  update drbg (entropy <> nonce <> ps)
  pure $! DRBG drbg
{-# INLINABLE new #-}
{-# SPECIALIZE new
  :: BS.ByteString -> BS.ByteString -> BS.ByteString -> IO (DRBG RealWorld) #-}
{-# SPECIALIZE new
  :: BS.ByteString -> BS.ByteString -> BS.ByteString -> ST s (DRBG s) #-}

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
        !(GHC.Word.W64# k00) <- PA.readPrimArray drbg 01
        !(GHC.Word.W64# k01) <- PA.readPrimArray drbg 02
        !(GHC.Word.W64# k02) <- PA.readPrimArray drbg 03
        !(GHC.Word.W64# k03) <- PA.readPrimArray drbg 04
        !(GHC.Word.W64# k04) <- PA.readPrimArray drbg 05
        !(GHC.Word.W64# k05) <- PA.readPrimArray drbg 06
        !(GHC.Word.W64# k06) <- PA.readPrimArray drbg 07
        !(GHC.Word.W64# k07) <- PA.readPrimArray drbg 08
        !(GHC.Word.W64# v00) <- PA.readPrimArray drbg 09
        !(GHC.Word.W64# v01) <- PA.readPrimArray drbg 10
        !(GHC.Word.W64# v02) <- PA.readPrimArray drbg 11
        !(GHC.Word.W64# v03) <- PA.readPrimArray drbg 12
        !(GHC.Word.W64# v04) <- PA.readPrimArray drbg 13
        !(GHC.Word.W64# v05) <- PA.readPrimArray drbg 14
        !(GHC.Word.W64# v06) <- PA.readPrimArray drbg 15
        !(GHC.Word.W64# v07) <- PA.readPrimArray drbg 16
        let !k0  = Registers (# k00, k01, k02, k03, k04, k05, k06, k07 #)
            !v0  = Registers (# v00, v01, v02, v03, v04, v05, v06, v07 #)
        !res <- gen_loop drbg k0 v0 bytes
        update drbg addl
        write_counter drbg (ctr + 1)
        pure $! Right res
{-# INLINABLE gen #-}
{-# SPECIALIZE gen
  :: DRBG RealWorld -> BS.ByteString -> Word64
  -> IO (Either Error BS.ByteString) #-}
{-# SPECIALIZE gen
  :: DRBG s -> BS.ByteString -> Word64
  -> ST s (Either Error BS.ByteString) #-}

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
  PA.setPrimArray drbg 01 08 (0x0000000000000000 :: Word64) -- init k
  PA.setPrimArray drbg 09 08 (0x0101010101010101 :: Word64) -- init v
  PA.setPrimArray drbg 17 16 (0x0000000000000000 :: Word64) -- init scratch
{-# INLINE wipe #-}

-- drbg utilities -------------------------------------------------------------

gen_loop
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word64
  -> Registers
  -> Registers
  -> Word64
  -> m BS.ByteString
gen_loop drbg k0 v0 bytes = loop mempty v0 0 where
  !vp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 72  -- 9 * 8
  !sp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 136 -- 17 * 8
  loop !acc v l
    | l >= bytes = do
        write_v drbg v
        pure acc
    | otherwise = do
        Prim.unsafeIOToPrim $ SHA512._hmac_rr vp sp k0 v
        !(GHC.Word.W64# nv0) <- PA.readPrimArray drbg 09
        !(GHC.Word.W64# nv1) <- PA.readPrimArray drbg 10
        !(GHC.Word.W64# nv2) <- PA.readPrimArray drbg 11
        !(GHC.Word.W64# nv3) <- PA.readPrimArray drbg 12
        !(GHC.Word.W64# nv4) <- PA.readPrimArray drbg 13
        !(GHC.Word.W64# nv5) <- PA.readPrimArray drbg 14
        !(GHC.Word.W64# nv6) <- PA.readPrimArray drbg 15
        !(GHC.Word.W64# nv7) <- PA.readPrimArray drbg 16
        let !nv = Registers (# nv0, nv1, nv2, nv3, nv4, nv5, nv6, nv7 #)
            !na = acc <> SHA512.cat nv
            !nl = l + 64
        loop na nv nl
{-# INLINE gen_loop #-}

update
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word64
  -> BS.ByteString
  -> m ()
update drbg provided_data@(BI.PS _ _ l) = do
  !(GHC.Word.W64# k00) <- PA.readPrimArray drbg 01
  !(GHC.Word.W64# k01) <- PA.readPrimArray drbg 02
  !(GHC.Word.W64# k02) <- PA.readPrimArray drbg 03
  !(GHC.Word.W64# k03) <- PA.readPrimArray drbg 04
  !(GHC.Word.W64# k04) <- PA.readPrimArray drbg 05
  !(GHC.Word.W64# k05) <- PA.readPrimArray drbg 06
  !(GHC.Word.W64# k06) <- PA.readPrimArray drbg 07
  !(GHC.Word.W64# k07) <- PA.readPrimArray drbg 08
  !(GHC.Word.W64# v00) <- PA.readPrimArray drbg 09
  !(GHC.Word.W64# v01) <- PA.readPrimArray drbg 10
  !(GHC.Word.W64# v02) <- PA.readPrimArray drbg 11
  !(GHC.Word.W64# v03) <- PA.readPrimArray drbg 12
  !(GHC.Word.W64# v04) <- PA.readPrimArray drbg 13
  !(GHC.Word.W64# v05) <- PA.readPrimArray drbg 14
  !(GHC.Word.W64# v06) <- PA.readPrimArray drbg 15
  !(GHC.Word.W64# v07) <- PA.readPrimArray drbg 16
  let !k0 = Registers (# k00, k01, k02, k03, k04, k05, k06, k07 #)
      !v0 = Registers (# v00, v01, v02, v03, v04, v05, v06, v07 #)
      !kp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 08  -- 1 * 8
      !vp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 72  -- 9 * 8
      !sp = PA.mutablePrimArrayContents drbg `FP.plusPtr` 136 -- 17 * 8
  Prim.unsafeIOToPrim $ SHA512._hmac_rsb kp sp k0 v0 0x00 provided_data
  !(GHC.Word.W64# k10) <- PA.readPrimArray drbg 01
  !(GHC.Word.W64# k11) <- PA.readPrimArray drbg 02
  !(GHC.Word.W64# k12) <- PA.readPrimArray drbg 03
  !(GHC.Word.W64# k13) <- PA.readPrimArray drbg 04
  !(GHC.Word.W64# k14) <- PA.readPrimArray drbg 05
  !(GHC.Word.W64# k15) <- PA.readPrimArray drbg 06
  !(GHC.Word.W64# k16) <- PA.readPrimArray drbg 07
  !(GHC.Word.W64# k17) <- PA.readPrimArray drbg 08
  let !k1 = Registers (# k10, k11, k12, k13, k14, k15, k16, k17 #)
  Prim.unsafeIOToPrim $ SHA512._hmac_rr vp sp k1 v0
  if   l == 0
  then pure ()
  else do
    !(GHC.Word.W64# v10) <- PA.readPrimArray drbg 09
    !(GHC.Word.W64# v11) <- PA.readPrimArray drbg 10
    !(GHC.Word.W64# v12) <- PA.readPrimArray drbg 11
    !(GHC.Word.W64# v13) <- PA.readPrimArray drbg 12
    !(GHC.Word.W64# v14) <- PA.readPrimArray drbg 13
    !(GHC.Word.W64# v15) <- PA.readPrimArray drbg 14
    !(GHC.Word.W64# v16) <- PA.readPrimArray drbg 15
    !(GHC.Word.W64# v17) <- PA.readPrimArray drbg 16
    let !v1 = Registers (# v10, v11, v12, v13, v14, v15, v16, v17 #)
    Prim.unsafeIOToPrim $ SHA512._hmac_rsb kp sp k1 v1 0x01 provided_data
    !(GHC.Word.W64# k20) <- PA.readPrimArray drbg 01
    !(GHC.Word.W64# k21) <- PA.readPrimArray drbg 02
    !(GHC.Word.W64# k22) <- PA.readPrimArray drbg 03
    !(GHC.Word.W64# k23) <- PA.readPrimArray drbg 04
    !(GHC.Word.W64# k24) <- PA.readPrimArray drbg 05
    !(GHC.Word.W64# k25) <- PA.readPrimArray drbg 06
    !(GHC.Word.W64# k26) <- PA.readPrimArray drbg 07
    !(GHC.Word.W64# k27) <- PA.readPrimArray drbg 08
    let !k2 = Registers (# k20, k21, k22, k23, k24, k25, k26, k27 #)
    Prim.unsafeIOToPrim $ SHA512._hmac_rr vp sp k2 v1
{-# INLINABLE update #-}
{-# SPECIALIZE update
  :: PA.MutablePrimArray RealWorld Word64 -> BS.ByteString -> IO () #-}
{-# SPECIALIZE update
  :: PA.MutablePrimArray s Word64 -> BS.ByteString -> ST s () #-}

init_counter
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word64
  -> m ()
init_counter drbg =
  PA.writePrimArray drbg 0 (0x01 :: Word64)
{-# INLINE init_counter #-}

read_counter
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word64
  -> m Word64
read_counter drbg = PA.readPrimArray drbg 0
{-# INLINE read_counter #-}

write_counter
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word64
  -> Word64
  -> m ()
write_counter drbg = PA.writePrimArray drbg 0
{-# INLINE write_counter #-}

write_v
  :: PrimMonad m
  => PA.MutablePrimArray (PrimState m) Word64
  -> Registers
  -> m ()
write_v drbg (R v0 v1 v2 v3 v4 v5 v6 v7) = do
  PA.writePrimArray drbg 09 (GHC.Word.W64# v0)
  PA.writePrimArray drbg 10 (GHC.Word.W64# v1)
  PA.writePrimArray drbg 11 (GHC.Word.W64# v2)
  PA.writePrimArray drbg 12 (GHC.Word.W64# v3)
  PA.writePrimArray drbg 13 (GHC.Word.W64# v4)
  PA.writePrimArray drbg 14 (GHC.Word.W64# v5)
  PA.writePrimArray drbg 15 (GHC.Word.W64# v6)
  PA.writePrimArray drbg 16 (GHC.Word.W64# v7)
{-# INLINE write_v #-}

-- read secret drbg state (for testing)
_read_v
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m BS.ByteString
_read_v (DRBG drbg) = do
  !v00 <- PA.readPrimArray drbg 09
  !v01 <- PA.readPrimArray drbg 10
  !v02 <- PA.readPrimArray drbg 11
  !v03 <- PA.readPrimArray drbg 12
  !v04 <- PA.readPrimArray drbg 13
  !v05 <- PA.readPrimArray drbg 14
  !v06 <- PA.readPrimArray drbg 15
  !v07 <- PA.readPrimArray drbg 16
  pure . BS.toStrict . BSB.toLazyByteString $ mconcat [
      BSB.word64BE v00
    , BSB.word64BE v01
    , BSB.word64BE v02
    , BSB.word64BE v03
    , BSB.word64BE v04
    , BSB.word64BE v05
    , BSB.word64BE v06
    , BSB.word64BE v07
    ]

-- read secret drbg state (for testing)
_read_k
  :: PrimMonad m
  => DRBG (PrimState m)
  -> m BS.ByteString
_read_k (DRBG drbg) = do
  !k00 <- PA.readPrimArray drbg 01
  !k01 <- PA.readPrimArray drbg 02
  !k02 <- PA.readPrimArray drbg 03
  !k03 <- PA.readPrimArray drbg 04
  !k04 <- PA.readPrimArray drbg 05
  !k05 <- PA.readPrimArray drbg 06
  !k06 <- PA.readPrimArray drbg 07
  !k07 <- PA.readPrimArray drbg 08
  pure . BS.toStrict . BSB.toLazyByteString $ mconcat [
      BSB.word64BE k00
    , BSB.word64BE k01
    , BSB.word64BE k02
    , BSB.word64BE k03
    , BSB.word64BE k04
    , BSB.word64BE k05
    , BSB.word64BE k06
    , BSB.word64BE k07
    ]
