{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.TripleSec.IO where

import Control.Exception

import Control.Monad.Trans.Class
import Control.Monad.IO.Class
import Control.Monad.Except
import Crypto.Random

import Crypto.TripleSec.Class
import Crypto.TripleSec.Internal (ByteArray)
import Crypto.TripleSec.Types

-- | Monad that works "out of the box" for encrypting/decrypting.
--
-- Does not throw exceptions (returns @Either TripleSecException ba@). Use with 'runTripleSecIO'.
type TripleSecIOM = TripleSecIOT IO

-- | Monad transformer for use with any IO based monad stack.
--
-- Does not throw exceptions (returns @Either TripleSecException a@). Use with 'runTripleSecIO'.
newtype TripleSecIOT m a = TripleSecIOT (ExceptT TripleSecException m a)
  deriving (Functor, Applicative, Monad, MonadIO, MonadError TripleSecException, MonadTrans)

instance MonadIO m => MonadRandom (TripleSecIOT m) where
  getRandomBytes n = TripleSecIOT $ (liftIO . getRandomBytes) n

instance Monad m => CanTripleSecDecrypt (TripleSecIOT m)
instance MonadIO m => CanTripleSec (TripleSecIOT m)

-- | Evaluate a 'TripleSecIOT' computation.
runTripleSecIO :: TripleSecIOT m a -> m (Either TripleSecException a)
runTripleSecIO (TripleSecIOT m) = runExceptT m

runInIO :: TripleSecIOM a -> IO a
runInIO action = do
  result <- runTripleSecIO action
  case result of Left err -> throwIO err
                 Right ba -> return ba

-- | 'encrypt' specialized to 'IO'. Throws instead of returning a 'TripleSecException'.
encryptIO :: (ByteArray ba)
          => ba       -- ^ Passphrase
          -> ba       -- ^ Plaintext
          -> IO ba
encryptIO pass plaintext = runInIO (encrypt pass plaintext)

-- | 'encryptWithCipher' specialized to 'IO'. Throws instead of returning a 'TripleSecException'.
encryptWithCipherIO :: ByteArray ba
                    => TripleSec ba
                    -> ba             -- ^ Ciphertext
                    -> IO ba
encryptWithCipherIO cipher plaintext = runInIO (encryptWithCipher cipher plaintext)

-- | 'newCipher' specialized to 'IO'. Throws instead of returning a 'TripleSecException'.
newCipherIO :: ByteArray ba
            => ba             -- ^ Passphrase
            -> IO (TripleSec ba)
newCipherIO password = runInIO (newCipher password)

-- | 'newCipherWithSalt' specialized to 'IO'. Throws instead of returning a 'TripleSecException'.
newCipherWithSaltIO :: ByteArray ba
                    => ba     -- ^ Passphrase
                    -> ba     -- ^ Salt
                    -> IO (TripleSec ba)
newCipherWithSaltIO password salt = runInIO (newCipherWithSalt password salt)


-- | 'decrypt' specialized to 'IO'. Throws instead of returning a 'TripleSecException'.
decryptIO :: ByteArray ba
          => ba     -- ^ Passphrase
          -> ba     -- ^ Ciphertext
          -> IO ba
decryptIO password ciphertext = runInIO (decrypt password ciphertext)

-- | 'decryptWithCipher' specialized to 'IO'. Throws instead of returning a 'TripleSecException'.
decryptWithCipherIO :: ByteArray ba
                    => TripleSec ba
                    -> ba   -- ^ Ciphertext
                    -> IO ba
decryptWithCipherIO cipher ciphertext = runInIO (decryptWithCipher cipher ciphertext)
