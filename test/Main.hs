{-# LANGUAGE OverloadedStrings #-}

module Main where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.DRBG.HMAC as DRBG
import qualified Data.ByteString as BS
import qualified Data.ByteString.Base16 as B16
import Data.Word (Word64)

-- XX test against
-- https://raw.githubusercontent.com/coruus/nist-testvectors/refs/heads/master/csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors/drbgvectors_pr_true/HMAC_DRBG.txt

fun0 = SHA256.hmac
add0 :: BS.ByteString
add0 = mempty
byts :: Word64
byts = 128

ent0 :: BS.ByteString
ent0 = "9969e54b4703ff31785b879a7e5c0eae0d3e309559e9fe96b0676d49d591ea4d"
non0 :: BS.ByteString
non0 = "07d20d46d064757d3023cac2376127ab"
per0 :: BS.ByteString
per0 = mempty
ent1 :: BS.ByteString
ent1 = "c60f2999100f738c10f74792676a3fc4a262d13721798046e29a295181569f54"
ent2 :: BS.ByteString
ent2 = "c11d4524c9071bd3096015fcf7bc24a607f22fa065c937658a2a77a8699089f4"

test func addl bytes i_ent i_non i_per g_ent0 g_ent1 = do
  let d_ent = B16.decodeLenient i_ent
      d_non = B16.decodeLenient i_non
      d_per = B16.decodeLenient i_per

  drbg <- DRBG.new func d_ent d_non d_per
  v0 <- DRBG._read_v drbg
  k0 <- DRBG._read_k drbg

  putStrLn $ "upon instantiation:"
  print $ "  v: " <> B16.encode v0
  print $ "  k: " <> B16.encode k0

  let d_ent0 = B16.decodeLenient g_ent0

  DRBG.reseed mempty d_ent0 drbg
  _ <- DRBG.gen addl bytes drbg
  v1 <- DRBG._read_v drbg
  k1 <- DRBG._read_k drbg

  putStrLn $ "after first gen:"
  print $ "  v: " <> B16.encode v1
  print $ "  k: " <> B16.encode k1

  let d_ent1 = B16.decodeLenient g_ent1

  DRBG.reseed mempty d_ent1 drbg
  res <- DRBG.gen addl bytes drbg
  v2 <- DRBG._read_v drbg
  k2 <- DRBG._read_k drbg

  putStrLn $ "after second gen:"
  print $ "  v: " <> B16.encode v2
  print $ "  k: " <> B16.encode k2

  putStrLn mempty

  putStrLn $ "returned bytes:"
  print $ "  " <> B16.encode res

main :: IO ()
main = test fun0 add0 byts ent0 non0 per0 ent1 ent2

