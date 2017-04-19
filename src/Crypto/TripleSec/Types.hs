module Crypto.TripleSec.Types where

import           Control.Exception.Safe
import           Crypto.Cipher.Twofish (Twofish256)
import           Crypto.Cipher.AES (AES256)

data TripleSec ba = TripleSec { passwordSalt :: ba
                              , hmacKeccak512 :: ba -> ba
                              , hmacSHA512 :: ba -> ba
                              , aes :: AES256
                              , twoFish :: Twofish256
                              , xSalsa :: ba }

data TripleSecException = DecryptionFailure DecryptionFailureType
                        | ZeroLengthPlaintext
                        | ZeroLengthPassword
                        | MisMatchedCipherSalt
                        | InvalidSaltLength
                        | TripleSecPanic String
                        deriving (Show, Typeable, Eq)

data DecryptionFailureType = InvalidCipherTextLength
                           | InvalidMagicBytes
                           | InvalidVersion
                           | InvalidSha512Hmac
                           | InvalidSha3Hmac
                           deriving (Show, Eq)

instance Exception TripleSecException
