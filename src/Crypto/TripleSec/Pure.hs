{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Crypto.TripleSec.Pure where

import Control.Monad.Trans.Class
import Control.Monad.State
import Control.Monad.Except
import Control.Monad.Identity
import Crypto.Random

import Crypto.TripleSec.Types
import Crypto.TripleSec.Class

-- | Monad that works "out of the box" for pure encrypting/decrypting.
--
-- Use with 'runTripleSecM' or 'evalTripleSecM'. 'SystemDRG' can be obtained with 'getSystemDRG'.
type TripleSecM = TripleSecT Identity

-- | Monad transformer for use with any non-IO based monad stack (See 'TripleSecIOT' for 'IO' based stacks).
--
-- Use with 'runTripleSecT' or 'evalTripleSecT'. 'SystemDRG' can be obtained with 'getSystemDRG'.
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

instance MonadTrans TripleSecT where
  lift = TripleSecT . lift . lift

-- | Evaluate a 'TripleSecT' computation.
--
-- If you have no use for the output 'SystemDRG'. See 'evalTripleSecT'.
runTripleSecT :: TripleSecT m a -> SystemDRG -> m (Either TripleSecException a, SystemDRG)
runTripleSecT (TripleSecT m) = runStateT (runExceptT m)

-- | Evaluate a 'TripleSecT' computation.
--
-- Do NOT re-use the input 'SystemDRG' (very bad!). See 'runTripleSecT' for an output 'SystemDRG' that's safe to use
-- elsewhere.
evalTripleSecT :: Functor m => TripleSecT m a -> SystemDRG -> m (Either TripleSecException a)
evalTripleSecT m gen = fmap fst (runTripleSecT m gen)

-- | Evaluate a 'TripleSecM' computation.
--
-- If you have no use for the output 'SystemDRG'. See 'evalTripleSecM'.
runTripleSecM :: TripleSecM a -> SystemDRG -> (Either TripleSecException a, SystemDRG)
runTripleSecM m gen = runIdentity (runTripleSecT m gen)

-- | Evaluate a 'TripleSecM' computation.
--
-- Do NOT re-use the input 'SystemDRG' (very bad!). See 'runTripleSecM' for an output 'SystemDRG' that's safe to use
-- elsewhere.
evalTripleSecM :: TripleSecM a -> SystemDRG -> Either TripleSecException a
evalTripleSecM m gen = runIdentity (evalTripleSecT m gen)