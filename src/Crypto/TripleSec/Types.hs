-- |
-- Module      : Crypto.TripleSec.Types
-- License     : BSD-style
-- Maintainer  : Sam Protas <sam.protas@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
module Crypto.TripleSec.Types where

import           Control.Exception
import           Data.Typeable

import           Crypto.Cipher.Twofish (Twofish256)
import           Crypto.Cipher.AES (AES256)


-- | TripleSec cipher used for encryption and decryption.
--
-- Dealing with this type is only necessary if you wish to use the somewhat lower-level API consisting of
-- 'encryptWithCipher' and 'decryptWithCipher'.
--
-- You can create a 'TripleSec' cipher with 'newCipher' or 'newCipherWithSalt'.
data TripleSec ba = TripleSec { passwordSalt :: ba
                              , hmacKeccak512 :: ba -> ba
                              , hmacSHA512 :: ba -> ba
                              , aes :: AES256
                              , twoFish :: Twofish256
                              , xSalsa :: ba }

-- | Exceptions thrown by this library.
--
--  For dealing with exceptions please see documentation for 'MonadThrow'.
data TripleSecException = DecryptionFailure DecryptionFailureType
                        | ZeroLengthPlaintext
                        | ZeroLengthPassword
                        | MisMatchedCipherSalt
                        | InvalidSaltLength
                        | TripleSecPanic String
                        deriving (Show, Typeable, Eq)

-- | Type describing possible 'DecryptionFailure'.
data DecryptionFailureType = InvalidCipherTextLength
                           | InvalidMagicBytes
                           | InvalidVersion
                           | InvalidSha512Hmac
                           | InvalidSha3Hmac
                           deriving (Show, Eq)

instance Exception TripleSecException
