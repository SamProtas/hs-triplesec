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
-- A tutorial for how to use this library can be found in @ Crypto.TripleSec.Tutorial @
--
module Crypto.TripleSec
    ( -- * Cipher Type
      TripleSec

      -- * Standard API
    , CanTripleSec (..)
    , CanTripleSecDecrypt (..)

      -- * Exception Types
    , TripleSecException (..)
    , CipherInitFailure (..)
    , EncryptionFailure (..)
    , DecryptionFailure (..)

      -- * Specialized IO API
    , encryptIO
    , decryptIO
    , newCipherIO
    , newCipherWithSaltIO
    , encryptWithCipherIO
    , decryptWithCipherIO

      -- * IO Based Monad API
    , TripleSecIOM
    , TripleSecIOT
    , runTripleSecIO

      -- * Pure Monad API
    , TripleSecM
    , TripleSecT
    , SystemDRG
    , getSystemDRG
    , runTripleSecM
    , evalTripleSecM
    , runTripleSecT
    , evalTripleSecT

      -- * Pure Decryption Only Monad API
    , TripleSecDecryptM
    , TripleSecDecryptT
    , runTripleSecDecryptM
    , runTripleSecDecryptT

      -- * Low Level Utils
    , checkPrefix
    , checkSalt
    , checkCipher
    ) where

import Crypto.Random

import Crypto.TripleSec.Types
import Crypto.TripleSec.Class
import Crypto.TripleSec.Pure
import Crypto.TripleSec.IO
import Crypto.TripleSec.Utils
