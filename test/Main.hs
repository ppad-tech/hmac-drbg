{-# OPTIONS_GHC -fno-warn-type-defaults #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Applicative ((<|>))
import qualified Crypto.Hash.SHA256 as SHA256
import qualified Crypto.Hash.SHA512 as SHA512
import qualified Crypto.DRBG.HMAC as DRBG
import qualified Data.Attoparsec.ByteString.Char8 as A
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import Test.Tasty
import Test.Tasty.HUnit

-- CAVP source:
--
-- https://raw.githubusercontent.com/coruus/nist-testvectors/refs/heads/master/csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors/drbgvectors_pr_true/HMAC_DRBG.txt
--
-- spec:
--
-- https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/DRBGVS.pdf

main :: IO ()
main = do
  sha256_vectors <- BS.readFile "etc/HMAC_DRBG_SHA256.txt"
  sha512_vectors <- BS.readFile "etc/HMAC_DRBG_SHA512.txt"
  let sha256_cases = case A.parseOnly parse_sha256_blocks sha256_vectors of
        Left _ -> error "ppad-hmac-drbg (test): parse error"
        Right cs -> cs

      sha512_cases = case A.parseOnly parse_sha512_blocks sha512_vectors of
        Left _ -> error "ppad-hmac-drbg (test): parse error"
        Right cs -> cs

  defaultMain (cavp_14_3 sha256_cases sha512_cases)

cavp_14_3 :: [CaseBlock] -> [CaseBlock] -> TestTree
cavp_14_3 cs ds = testGroup "CAVP 14.3" [
    testGroup "HMAC-SHA256" (fmap (execute_caseblock SHA256.hmac) cs)
  , testGroup "HMAC-SHA512" (fmap (execute_caseblock SHA512.hmac) ds)
  ]

data CaseBlock = CaseBlock {
    cb_blockHeader :: !BlockHeader
  , cb_cases       :: ![Case]
  } deriving Show

data BlockHeader = BlockHeader {
    bh_EntropyInputLen          :: !Int
  , bh_NonceLen                 :: !Int
  , bh_PersonalizationStringLen :: !Int
  , bh_AdditionalInputLen       :: !Int
  , bh_ReturnedBitsLen          :: !Int
  } deriving Show

-- test case spec
data Case = Case {
    caseCount    :: !Int
  -- instantiate
  , caseEntropy0 :: !BS.ByteString
  , caseNonce    :: !BS.ByteString
  , casePs       :: !BS.ByteString
  , caseV0       :: !BS.ByteString
  , caseK0       :: !BS.ByteString
  -- first generate
  , caseAddl1    :: !BS.ByteString
  , caseEntropy1 :: !BS.ByteString
  , caseV1       :: !BS.ByteString
  , caseK1       :: !BS.ByteString
  -- second generate
  , caseAddl2    :: !BS.ByteString
  , caseEntropy2 :: !BS.ByteString
  , caseV2       :: !BS.ByteString
  , caseK2       :: !BS.ByteString
  , caseReturned :: !BS.ByteString
  } deriving Show

execute_caseblock :: DRBG.HMAC -> CaseBlock -> TestTree
execute_caseblock hmac CaseBlock {..} =
    testGroup msg (fmap (execute hmac) cb_cases)
  where
    BlockHeader {..} = cb_blockHeader
    msg = "bitlens: " <>
          "ent " <> show bh_EntropyInputLen <> " " <>
          "non " <> show bh_NonceLen <> " " <>
          "per " <> show bh_PersonalizationStringLen <> " " <>
          "add " <> show bh_AdditionalInputLen <> " " <>
          "ret " <> show bh_ReturnedBitsLen

-- execute test case
execute :: DRBG.HMAC -> Case -> TestTree
execute hmac Case {..} = testCase ("count " <> show caseCount) $ do
  let bytes = fromIntegral (BS.length caseReturned)

  drbg <- DRBG.new hmac caseEntropy0 caseNonce casePs
  v0 <- DRBG._read_v drbg
  k0 <- DRBG._read_k drbg

  assertEqual "v0" v0 caseV0
  assertEqual "k0" k0 caseK0

  DRBG.reseed caseEntropy1 caseAddl1 drbg
  _ <- DRBG.gen mempty bytes drbg
  v1 <- DRBG._read_v drbg
  k1 <- DRBG._read_k drbg

  assertEqual "v1" v1 caseV1
  assertEqual "k1" k1 caseK1

  DRBG.reseed caseEntropy2 caseAddl2 drbg
  returned <- DRBG.gen mempty bytes drbg
  v2 <- DRBG._read_v drbg
  k2 <- DRBG._read_k drbg

  assertEqual "returned_bytes" returned caseReturned
  assertEqual "v2" v2 caseV2
  assertEqual "k2" k2 caseK2

-- CAVP vector parsers

hex_digit :: A.Parser Char
hex_digit = A.satisfy hd where
  hd c =
       (c >= '0' && c <= '9')
    || (c >= 'a' && c <= 'f')
    || (c >= 'A' && c <= 'F')

parse_hex :: A.Parser BS.ByteString
parse_hex = (B16.decodeLenient . B8.pack) <$> A.many1 hex_digit

parse_kv :: BS.ByteString -> A.Parser BS.ByteString
parse_kv k =
       A.string k
    *> A.skipSpace
    *> A.char '='
    *> parse_v
  where
    parse_v =
          (A.endOfLine *> pure mempty)
      <|> (A.skipSpace *> parse_hex <* A.endOfLine)

parse_case :: A.Parser Case
parse_case = do
  caseCount    <- A.string "COUNT = " *> A.decimal <* A.endOfLine
  caseEntropy0 <- parse_kv "EntropyInput"
  caseNonce    <- parse_kv "Nonce"
  casePs       <- parse_kv "PersonalizationString"
  A.string "** INSTANTIATE:" *> A.endOfLine
  caseV0       <- parse_kv "\tV"
  caseK0       <- parse_kv "\tKey"
  caseAddl1    <- parse_kv "AdditionalInput"
  caseEntropy1 <- parse_kv "EntropyInputPR"
  A.string "** GENERATE (FIRST CALL):" *> A.endOfLine
  caseV1       <- parse_kv "\tV"
  caseK1       <- parse_kv "\tKey"
  caseAddl2    <- parse_kv "AdditionalInput"
  caseEntropy2 <- parse_kv "EntropyInputPR"
  caseReturned <- parse_kv "ReturnedBits"
  A.string "** GENERATE (SECOND CALL):" *> A.endOfLine
  caseV2       <- parse_kv "\tV"
  caseK2       <- parse_kv "\tKey"
  return Case {..}

parse_cases :: A.Parser [Case]
parse_cases = parse_case `A.sepBy` A.endOfLine

parse_header :: BS.ByteString -> A.Parser BlockHeader
parse_header sha = do
    A.string ("[" <> sha <> "]") *> A.endOfLine
    A.string "[PredictionResistance = True]" *> A.endOfLine
    bh_EntropyInputLen <-
      A.string "[EntropyInputLen = " *> A.decimal <* A.string "]" <* A.endOfLine
    bh_NonceLen <-
      A.string "[NonceLen = " *> A.decimal <* A.string "]" <* A.endOfLine
    bh_PersonalizationStringLen <-
         A.string "[PersonalizationStringLen = " *> A.decimal <* A.string "]"
      <* A.endOfLine
    bh_AdditionalInputLen <-
         A.string "[AdditionalInputLen = " *> A.decimal <* A.string "]"
      <* A.endOfLine
    bh_ReturnedBitsLen <-
         A.string "[ReturnedBitsLen = " *> A.decimal <* A.string "]"
      <* A.endOfLine
    A.endOfLine
    pure BlockHeader {..}

parse_sha256_block :: A.Parser CaseBlock
parse_sha256_block = do
  cb_blockHeader <- parse_header "SHA-256"
  cb_cases <- parse_cases
  A.endOfLine
  pure CaseBlock {..}

parse_sha256_blocks :: A.Parser [CaseBlock]
parse_sha256_blocks = A.many1 parse_sha256_block

parse_sha512_block :: A.Parser CaseBlock
parse_sha512_block = do
  cb_blockHeader <- parse_header "SHA-512"
  cb_cases <- parse_cases
  A.endOfLine
  pure CaseBlock {..}

parse_sha512_blocks :: A.Parser [CaseBlock]
parse_sha512_blocks = A.many1 parse_sha512_block

