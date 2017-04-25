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

type TripleSecIOM = TripleSecIOT IO

newtype TripleSecIOT m a = TripleSecIOT (ExceptT TripleSecException m a)
  deriving (Functor, Applicative, Monad, MonadIO, MonadError TripleSecException, MonadTrans)

instance MonadIO m => MonadRandom (TripleSecIOT m) where
  getRandomBytes n = TripleSecIOT $ (liftIO . getRandomBytes) n

instance Monad m => CanTripleSecDecrypt (TripleSecIOT m)
instance MonadIO m => CanTripleSec (TripleSecIOT m)

runTripleSecIO :: TripleSecIOT m a -> m (Either TripleSecException a)
runTripleSecIO (TripleSecIOT m) = runExceptT m

runInIO :: TripleSecIOM a -> IO a
runInIO action = do
  result <- runTripleSecIO action
  case result of Left err -> throwIO err
                 Right ba -> return ba

encryptIO :: (ByteArray ba) => ba -> ba -> IO ba
encryptIO pass plaintext = runInIO (encrypt pass plaintext)

encryptWithCipherIO :: ByteArray ba => TripleSec ba -> ba -> IO ba
encryptWithCipherIO cipher plaintext = runInIO (encryptWithCipher cipher plaintext)

newCipherIO :: ByteArray ba => ba -> IO (TripleSec ba)
newCipherIO password = runInIO (newCipher password)

newCipherWithSaltIO :: ByteArray ba => ba -> ba -> IO (TripleSec ba)
newCipherWithSaltIO password salt = runInIO (newCipherWithSalt password salt)

decryptIO :: ByteArray ba => ba -> ba -> IO ba
decryptIO password ciphertext = runInIO (decrypt password ciphertext)

decryptWithCipherIO :: ByteArray ba => TripleSec ba -> ba -> IO ba
decryptWithCipherIO cipher ciphertext = runInIO (decryptWithCipher cipher ciphertext)
