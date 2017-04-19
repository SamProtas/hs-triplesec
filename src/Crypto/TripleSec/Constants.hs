{-# LANGUAGE DuplicateRecordFields #-}
module Crypto.TripleSec.Constants where

import Data.Word

import qualified Crypto.KDF.Scrypt as Scrypt

import qualified Crypto.TripleSec.Internal as I
import           Crypto.TripleSec.Internal (ByteArray)


magicBytes :: [Word8]
magicBytes = [0x1c, 0x94, 0xd7, 0xde]

packedMagicBytes :: ByteArray ba => ba
packedMagicBytes = I.pack magicBytes

versionBytes :: [Word8]
versionBytes = [0x00, 0x00, 0x00, 0x03]

packedVersionBytes :: ByteArray ba => ba
packedVersionBytes = I.pack versionBytes

saltLen, macOutputLen, macKeyLen, cipherKeyLen, ivLen, salsaIvLen, totalIvLen, dkLen, overhead :: Int

saltLen = 16
macOutputLen = 64
macKeyLen = 48
cipherKeyLen = 32
ivLen = 16
salsaIvLen = 24
totalIvLen = 2 * ivLen + salsaIvLen
dkLen = 2 * macKeyLen + 3 * cipherKeyLen

overhead = length magicBytes + length versionBytes + saltLen + 2 * macOutputLen + totalIvLen

paramsScrypt :: Scrypt.Parameters
paramsScrypt = Scrypt.Parameters { n = (2 :: Word64) ^ (15 :: Word64)
                                 , r = 8
                                 , p = 1
                                 , outputLength = dkLen }
