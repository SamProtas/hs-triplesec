{-# LANGUAGE OverloadedStrings #-}
module Crypto.TripleSec
    ( -- Types
      TripleSec

      -- Exception Types
    , TripleSecException (..)
    , DecryptionFailureType (..)

      -- API
    , encrypt
    , decrypt

    -- Lower level API
    , newCipher
    , newCipherWithSalt
    , encryptWithCipher
    , decryptWithCipher

      -- Low level utils
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


encrypt :: (ByteArray ba, MonadThrow m, MonadRandom m) => ba -> ba -> m ba
encrypt pass plaintext = do
  cipher <- newCipher pass
  encryptWithCipher cipher plaintext

decrypt :: (ByteArray ba, MonadThrow m) => ba -> ba -> m ba
decrypt pass cipherText = do
  (prefix, providedSalt, lessPrefix) <- checkPrefix cipherText
  decryptor <- newCipherWithSalt pass providedSalt
  decryptCommon decryptor prefix lessPrefix

newCipher :: (ByteArray ba, MonadThrow m, MonadRandom m) => ba -> m (TripleSec ba)
newCipher pass = do
  salt <- getRandomBytes saltLen
  newCipherWithSalt pass salt

newCipherWithSalt :: (ByteArray ba, MonadThrow m) => ba -> ba -> m (TripleSec ba)
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

encryptWithCipher :: (ByteArray ba, MonadThrow m, MonadRandom m) => TripleSec ba -> ba -> m ba
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

decryptWithCipher :: (ByteArray ba, MonadThrow m) => TripleSec ba -> ba -> m ba
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
