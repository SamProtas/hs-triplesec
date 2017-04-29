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
data TripleSecException = CipherInitException CipherInitFailure
                        | EncryptionException EncryptionFailure
                        | DecryptionException DecryptionFailure
                        deriving (Show, Eq, Typeable)

instance Exception TripleSecException

-- | Possible cipher initialization failures
data CipherInitFailure = ZeroLengthPassword
                       | InvalidSaltLength
                       deriving (Show, Eq)

-- | Possible encryption failures
data EncryptionFailure = ZeroLengthPlaintext
                       deriving (Show, Eq)

-- | Possible decryption Failures
data DecryptionFailure = InvalidCipherTextLength
                       | InvalidMagicBytes
                       | InvalidVersion
                       | InvalidSha512Hmac
                       | InvalidKeccakHmac
                       | MisMatchedCipherSalt
                       deriving (Show, Eq)

