-- |
-- Module      : Crypto.TripleSec
-- License     : BSD-style
-- Maintainer  : Sam Protas <sam.protas@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- TripleSec is a simple, triple-paranoid, symmetric encryption library.
--
-- <https://keybase.io/triplesec/>
--
{-# LANGUAGE OverloadedStrings #-}
module Crypto.TripleSec
    ( -- * Standard API
      encrypt
    , decrypt

      -- * Exception Types
    , TripleSecException (..)
    , DecryptionFailureType (..)

     -- * Types
    , TripleSec

    -- * Lower Level API
    , newCipher
    , encryptWithCipher
    , decryptWithCipher
    , newCipherWithSalt

    -- * Low Level Utils
    , checkPrefix
    , checkSalt
    , checkCipher
    ) where

import           Data.Maybe
import           Data.Monoid ((<>))
import           Control.Monad (when)

import           Control.Exception.Safe
import qualified Crypto.Cipher.XSalsa as XSalsa
import qualified Crypto.KDF.Scrypt as Scrypt
import           Crypto.Random
import           Crypto.Cipher.Types (ctrCombine, makeIV)
import           Crypto.Hash.Algorithms (SHA512, Keccak_512)
import           Crypto.MAC.HMAC

import           Crypto.TripleSec.Internal (ByteArray, convert)
import qualified Crypto.TripleSec.Internal as I
import           Crypto.TripleSec.Constants
import           Crypto.TripleSec.Types
import           Crypto.TripleSec.Utils

-- | Encrypt a plaintext with a passphrase. Can throw a 'TripleSecException'.
encrypt :: (ByteArray ba, MonadThrow m, MonadRandom m)
        => ba     -- ^ Passphrase
        -> ba     -- ^ Plaintext
        -> m ba   -- ^ Ciphertext
encrypt pass plaintext = do
  cipher <- newCipher pass
  encryptWithCipher cipher plaintext

-- | Decrypt a ciphertext with a passphrase. Can throw a 'TripleSecException'.
decrypt :: (ByteArray ba, MonadThrow m)
        => ba     -- ^ Passphrase
        -> ba     -- ^ Ciphertext
        -> m ba   -- ^ Plaintext
decrypt pass cipherText = do
  (prefix, providedSalt, lessPrefix) <- checkPrefix cipherText
  decryptor <- newCipherWithSalt pass providedSalt
  decryptCommon decryptor prefix lessPrefix

-- | Create a new 'TripleSec' cipher. Can throw a 'TripleSecException'.
newCipher :: (ByteArray ba, MonadThrow m, MonadRandom m) => ba -> m (TripleSec ba)
newCipher pass = do
  salt <- getRandomBytes saltLen
  newCipherWithSalt pass salt

-- | Create a new 'TripleSec' cipher with a provided salt. Can throw a 'TripleSecException'.
--
-- Creating a cipher with a specific salt is useful if you know you have several ciphertexts to decrypt, all of which
-- were encrypted with the same cipher (salt + passphrase). Creating the cipher once up front allows you to save
-- time, cpu, and memory by avoiding the expensive key-derivation on subsequent decryptions.
newCipherWithSalt :: (ByteArray ba, MonadThrow m)
                  => ba     -- ^ Passphrase
                  -> ba     -- ^ Salt
                  -> m (TripleSec ba)
newCipherWithSalt pass salt = do
  checkSalt salt
  when (I.length pass == 0) $ throw ZeroLengthPassword
  let dk = Scrypt.generate paramsScrypt pass salt
  let macKeys =I.take (macKeyLen * 2) dk
  let sha512Key = I.take macKeyLen macKeys
  let keccak512Key = I.drop macKeyLen macKeys
  let cipherKeys = I.drop (macKeyLen * 2) dk
  let aesKey = I.take cipherKeyLen cipherKeys
  let twoFishKey = I.take cipherKeyLen $ I.drop cipherKeyLen cipherKeys
  let xSalsaKey  = I.drop (cipherKeyLen * 2) cipherKeys
  twoFishCipher <- cipherInitOrPanic twoFishKey
  aesCipher <- cipherInitOrPanic aesKey
  return TripleSec { passwordSalt = salt
                   , hmacKeccak512 = convert . (hmac keccak512Key :: ByteArray ba => ba -> HMAC Keccak_512)
                   , hmacSHA512 = convert . (hmac sha512Key :: ByteArray ba => ba -> HMAC SHA512)
                   , aes = aesCipher
                   , twoFish = twoFishCipher
                   , xSalsa = xSalsaKey }

-- | Encrypt a plaintext with a 'TripleSec' cipher. Can throw a 'TripleSecException'.
--
-- This function allows encrypting multiple plaintexts without continually paying for the expensive key-derivation
-- process. Please consider your use case and any risks that come from repeated usage of the same salt.
--
-- For a simpler alternative, please see 'encrypt'.
encryptWithCipher :: (ByteArray ba, MonadThrow m, MonadRandom m)
                  => TripleSec ba
                  -> ba     -- ^ Plaintext
                  -> m ba
encryptWithCipher cipher plaintext = do
  when (I.length plaintext == 0) $ throw ZeroLengthPlaintext
  let prefix = packedMagicBytes <> packedVersionBytes <> passwordSalt cipher
  ivs <- getRandomBytes totalIvLen
  let (aesIv, lessAesIv) = I.splitAt ivLen ivs
  let (twoFishIv, xSalsaIv) = I.splitAt ivLen lessAesIv
  let xSalsaCipher = XSalsa.initialize 20 (xSalsa cipher) xSalsaIv
  let xSalsaEncrypted = xSalsaIv <> xSalsaCombine xSalsaCipher plaintext
  let twoFishEncrypted = twoFishIv <> ctrCombine (twoFish cipher) (fromJust $ makeIV twoFishIv) xSalsaEncrypted
  let aesEncrypted = aesIv <> ctrCombine (aes cipher) (fromJust $ makeIV aesIv) twoFishEncrypted
  let sha3HMACed = hmacKeccak512 cipher $ prefix <> aesEncrypted
  let sha512HMACed = hmacSHA512 cipher $ prefix <> aesEncrypted
  return $
    prefix <>
    sha512HMACed <>
    sha3HMACed <>
    aesEncrypted

-- | Decrypt a ciphertext with a 'TripleSec' cipher. Can throw a 'TripleSecException'.
--
-- This function allows decrypting multiple ciphertexts without continually paying for the expensive key-derivation
-- process. This function will only work if the given cipher's salt matches that of the ciphertext, otherwise it throws
-- a 'MisMatchedCipherSalt'.
--
-- For a simpler alternative, please see 'decrypt'.
decryptWithCipher :: (ByteArray ba, MonadThrow m)
                  => TripleSec ba
                  -> ba     -- ^ Ciphertext
                  -> m ba
decryptWithCipher cipher cipherText = do
  (prefix, providedSalt, lessPrefix) <- checkPrefix cipherText
  checkCipher cipher providedSalt
  decryptCommon cipher prefix lessPrefix

decryptCommon :: (ByteArray ba, MonadThrow m) => TripleSec ba -> ba -> ba -> m ba
decryptCommon cipher prefix macsAndEncrypted = do
  let (providedSHA512, lessSHA512) = I.splitAt macOutputLen macsAndEncrypted
  let (providedSHA3, encryptedPayload) = I.splitAt macOutputLen lessSHA512
  let toMac = prefix <> encryptedPayload
  when (providedSHA512 /= hmacSHA512 cipher toMac) $ throw $ DecryptionFailure InvalidSha512Hmac
  when (providedSHA3 /= hmacKeccak512 cipher toMac) $ throw $ DecryptionFailure InvalidSha3Hmac
  let (aesIV, lessAESiv) = I.splitAt ivLen encryptedPayload
  let aesDecrypted = ctrCombine (aes cipher) (fromJust $ makeIV aesIV) lessAESiv
  let (twoFishIV, lessTwoFishIv) = I.splitAt ivLen aesDecrypted
  let twoFishDecrypted = ctrCombine (twoFish cipher) (fromJust $ makeIV twoFishIV) lessTwoFishIv
  let (xSalsaIV, lessXSalsaIV) = I.splitAt salsaIvLen twoFishDecrypted

  return $ xSalsaCombine (initXSalsa (xSalsa cipher) xSalsaIV) lessXSalsaIV
