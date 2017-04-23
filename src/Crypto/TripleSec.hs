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
module Crypto.TripleSec
    ( -- * Cipher Type
      TripleSec

      -- * Standard API
    , CanTripleSec (..)
    , CanTripleSecDecrypt (..)

      -- * Exception Types
    , TripleSecException (..)
    , DecryptionFailureType (..)

      -- * Specialized IO API
    , encryptIO
    , decryptIO
    , newCipherIO
    , newCipherWithSaltIO
    , encryptWithCipherIO
    , decryptWithCipherIO

      -- * IO Based Monad API
    , TripleSecIO
    , runTripleSecIO

      -- * Pure Monad API
    , TripleSecM
    , TripleSecT
    , getSystemDRG
    , runTripleSecM
    , evalTripleSecM
    , runTripleSecT
    , evalTripleSecT

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
