module Utils where

import Control.Monad (guard)
import Data.Monoid ((<>))

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Data.ByteArray.Encoding
import Control.Exception

import Crypto.TripleSec


type Password = ByteString
type PlainText = ByteString
type HexEncodedCipherText = ByteString

newtype NonEmptyByteString = NonEmptyByteString ByteString deriving Show

instance Arbitrary NonEmptyByteString where
  arbitrary = suchThat (NonEmptyByteString <$> arbitrary) (\(NonEmptyByteString generated) -> B.length generated >= 1)

instance Arbitrary ByteString where
  arbitrary = B.pack `fmap` arbitrary

makeKatTestTree :: ((Password, PlainText, HexEncodedCipherText), Int) -> TestTree
makeKatTestTree ((pw, expected, hex), ind) = testCase ("KAT #" <> show ind) $ do
  let (Right raw) = convertFromBase Base16 hex
  decrypted <- decryptIO pw raw
  expected @=? decrypted

assertException :: (Exception e, Eq e) => e -> IO a -> IO ()
assertException ex action =
    handleJust isWanted (const $ return ()) $ do
        _ <- action
        assertFailure $ "Expected exception: " ++ show ex
  where isWanted = guard . (== ex)