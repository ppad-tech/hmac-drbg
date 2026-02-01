{-# OPTIONS_GHC -fno-warn-type-defaults #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import Control.Applicative ((<|>))
import qualified Crypto.DRBG.HMAC.SHA256 as DRBG256
import qualified Crypto.DRBG.HMAC.SHA512 as DRBG512
import qualified Data.Attoparsec.ByteString.Char8 as A
import qualified Data.ByteString as BS
import Data.Word (Word64)
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
    testGroup "HMAC-SHA256" (fmap (execute_caseblock DRBG256.new DRBG256.reseed DRBG256.gen DRBG256._read_v DRBG256._read_k) cs)
  , testGroup "HMAC-SHA512" (fmap (execute_caseblock DRBG512.new DRBG512.reseed DRBG512.gen DRBG512._read_v DRBG512._read_k) ds)
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

execute_caseblock
  :: (BS.ByteString -> BS.ByteString -> BS.ByteString -> IO drbg)
  -> (drbg -> BS.ByteString -> BS.ByteString -> IO ())
  -> (drbg -> BS.ByteString -> Word64 -> IO (Either e BS.ByteString))
  -> (drbg -> IO BS.ByteString)
  -> (drbg -> IO BS.ByteString)
  -> CaseBlock
  -> TestTree
execute_caseblock drbg_new drbg_reseed drbg_gen read_v read_k CaseBlock {..} =
    testGroup msg (fmap (execute drbg_new drbg_reseed drbg_gen read_v read_k) cb_cases)
  where
    BlockHeader {..} = cb_blockHeader
    msg = "bitlens: " <>
          "ent " <> show bh_EntropyInputLen <> " " <>
          "non " <> show bh_NonceLen <> " " <>
          "per " <> show bh_PersonalizationStringLen <> " " <>
          "add " <> show bh_AdditionalInputLen <> " " <>
          "ret " <> show bh_ReturnedBitsLen

-- execute test case
execute
  :: (BS.ByteString -> BS.ByteString -> BS.ByteString -> IO drbg)
  -> (drbg -> BS.ByteString -> BS.ByteString -> IO ())
  -> (drbg -> BS.ByteString -> Word64 -> IO (Either e BS.ByteString))
  -> (drbg -> IO BS.ByteString)
  -> (drbg -> IO BS.ByteString)
  -> Case
  -> TestTree
execute drbg_new drbg_reseed drbg_gen read_v read_k Case {..} =
    testCase ("count " <> show caseCount) $ do
  let bytes = fromIntegral (BS.length caseReturned)

  drbg <- drbg_new caseEntropy0 caseNonce casePs
  v0 <- read_v drbg
  k0 <- read_k drbg

  assertEqual "v0" v0 caseV0
  assertEqual "k0" k0 caseK0

  drbg_reseed drbg caseEntropy1 caseAddl1
  Right _ <- drbg_gen drbg mempty bytes
  v1 <- read_v drbg
  k1 <- read_k drbg

  assertEqual "v1" v1 caseV1
  assertEqual "k1" k1 caseK1

  drbg_reseed drbg caseEntropy2 caseAddl2
  Right returned <- drbg_gen drbg mempty bytes
  v2 <- read_v drbg
  k2 <- read_k drbg

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
parse_hex = (decodeLenient . B8.pack) <$> A.many1 hex_digit where
  decodeLenient bs = case B16.decode bs of
    Nothing -> error "bang"
    Just v -> v

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

