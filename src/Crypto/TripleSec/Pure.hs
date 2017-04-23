{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.TripleSec.Pure where

import Control.Monad.Trans
import Control.Monad.State
import Control.Monad.Except
import Control.Monad.Identity
import Crypto.Random

import Crypto.TripleSec.Types
import Crypto.TripleSec.Class


type TripleSecM = TripleSecT Identity

newtype TripleSecT m a = TripleSecT (ExceptT TripleSecException (StateT SystemDRG  m) a)
  deriving (Functor, Applicative, Monad, MonadError TripleSecException)

instance Monad m => MonadRandom (TripleSecT m) where
  getRandomBytes n = TripleSecT $ do
    gen <- get
    let (bytes, newGen) = randomBytesGenerate n gen
    put newGen
    return bytes

instance Monad m => CanTripleSecDecrypt (TripleSecT m)
instance Monad m => CanTripleSec (TripleSecT m)

runTripleSecT :: Monad m => TripleSecT m a -> SystemDRG -> m (Either TripleSecException a, SystemDRG)
runTripleSecT (TripleSecT m) = runStateT (runExceptT m)

evalTripleSecT :: Monad m => TripleSecT m a -> SystemDRG -> m (Either TripleSecException a)
evalTripleSecT m gen = fmap fst (runTripleSecT m gen)

runTripleSecM :: TripleSecM a -> SystemDRG -> (Either TripleSecException a, SystemDRG)
runTripleSecM m gen = runIdentity (runTripleSecT m gen)

evalTripleSecM :: TripleSecM a -> SystemDRG -> Either TripleSecException a
evalTripleSecM m gen = runIdentity (evalTripleSecT m gen)