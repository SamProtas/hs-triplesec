
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

checkCipher :: (ByteArray ba, MonadThrow m) => TripleSec ba -> ba -> m ()
checkCipher cipher providedSalt = when (providedSalt /= passwordSalt cipher) (throw MisMatchedCipherSalt)

checkPrefix :: (ByteArray ba, MonadThrow m) => ba -> m (ba, ba, ba)
checkPrefix cipherText = checkLength cipherText >> checkMagicBytes cipherText >>= checkVersionBytes

checkSalt :: (ByteArray ba, MonadThrow m) => ba -> m ()
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
