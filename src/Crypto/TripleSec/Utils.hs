-- |
-- Module      : Crypto.TripleSec.Utils
-- License     : BSD-style
-- Maintainer  : Sam Protas <sam.protas@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
module Crypto.TripleSec.Utils where

import           Data.Monoid ((<>))
import           Control.Monad (when)

import           Control.Exception.Safe
import           Crypto.Error
import           Crypto.Cipher.Types hiding (Cipher)
import qualified Crypto.Cipher.XSalsa as XSalsa

import           Crypto.TripleSec.Internal (ByteArray)
import qualified Crypto.TripleSec.Internal as I
import           Crypto.TripleSec.Types
import           Crypto.TripleSec.Constants


panic :: (Show e, MonadThrow m) => e -> m b
panic = throw . TripleSecPanic . show

cipherInitOrPanic :: (ByteArray ba, MonadThrow m, BlockCipher c) => ba -> m c
cipherInitOrPanic key = case cipherInit key of CryptoFailed err -> panic err
                                               CryptoPassed cipher -> return cipher

initXSalsa :: ByteArray ba => ba -> ba -> XSalsa.State
initXSalsa = XSalsa.initialize 20

xSalsaCombine :: ByteArray ba => XSalsa.State -> ba -> ba
xSalsaCombine state input = output
  where (output, _) = XSalsa.combine state input

-- | Utility function to check that the provided 'TripleSec' was built with the provided salt. Can throw a
-- 'MisMatchedCipherSalt'.
--
-- This function does /not/ confirm anything about the passphrase provided when the 'TripleSec' cipher was created
-- or the passphrase used to encrypt a ciphertext where the salt came from.
checkCipher :: (ByteArray ba, MonadThrow m)
            => TripleSec ba
            -> ba             -- ^ Salt
            -> m ()
checkCipher cipher providedSalt = when (providedSalt /= passwordSalt cipher) (throw MisMatchedCipherSalt)

-- | Utility function to check that ciphertext is structurally valid and encrypted with a supported TripleSec version.
-- Can throw a 'TripleSecException'.
--
-- This function can be used for extracting the salt from a ciphertext to build a cipher with 'newCipherWithSalt'. If
-- you know you've encrypted many things with the same cipher this lets you decrypt them all without continually paying
-- for the expensive key-derivation.
--
-- The only potentially useful output as a consumer of this library is the salt.
checkPrefix :: (ByteArray ba, MonadThrow m)
            => ba               -- ^ Ciphertext
            -> m (ba, ba, ba)   -- ^ (TripleSec prefix, Salt, encrypted payload)
checkPrefix cipherText = checkLength cipherText >> checkMagicBytes cipherText >>= checkVersionBytes


-- | Utility function to check salt length. Can throw an 'InvalidSaltLength'.
checkSalt :: (ByteArray ba, MonadThrow m)
          => ba     -- ^ Salt
          -> m ()
checkSalt salt = when (I.length salt /= saltLen) $ throw InvalidSaltLength

checkLength :: (ByteArray ba, MonadThrow m) => ba -> m ()
checkLength cipherText = when (I.length cipherText <= overhead) $ throw $ DecryptionFailure InvalidCipherTextLength

checkMagicBytes :: (ByteArray ba, MonadThrow m) => ba -> m (ba, ba)
checkMagicBytes cipherText = do
  let (providedMagicBytes, lessMagicBytes) = I.splitAt (length magicBytes) cipherText
  when (providedMagicBytes /= packedMagicBytes) $ throw $ DecryptionFailure InvalidMagicBytes
  return (providedMagicBytes, lessMagicBytes)

checkVersionBytes :: (ByteArray ba, MonadThrow m) => (ba, ba) -> m (ba, ba, ba)
checkVersionBytes (providedMagicBytes, lessMagicBytes) = do
  let (providedVersionBytes, lessVersion) = I.splitAt (length versionBytes) lessMagicBytes
  when (providedVersionBytes /= packedVersionBytes) $ throw $ DecryptionFailure InvalidVersion
  let (providedSalt, lessPrefix) = I.splitAt saltLen lessVersion
  let prefix = providedMagicBytes <> providedVersionBytes <> providedSalt
  return (prefix, providedSalt, lessPrefix)
