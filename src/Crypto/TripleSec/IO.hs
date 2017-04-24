{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.TripleSec.IO where

import Control.Exception

import Control.Monad.IO.Class
import Control.Monad.Except
import Crypto.Random

import Crypto.TripleSec.Class
import Crypto.TripleSec.Internal (ByteArray)
import Crypto.TripleSec.Types


newtype TripleSecIO a = TripleSecIO (ExceptT TripleSecException IO a)
  deriving (Functor, Applicative, Monad, MonadIO, MonadError TripleSecException)

instance MonadRandom TripleSecIO where
  getRandomBytes n = TripleSecIO $ (liftIO . getRandomBytes) n

instance CanTripleSecDecrypt TripleSecIO
instance CanTripleSec TripleSecIO

runTripleSecIO :: TripleSecIO a -> IO (Either TripleSecException a)
runTripleSecIO (TripleSecIO m) = runExceptT m

runInIO :: TripleSecIO a -> IO a
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
