{-# LANGUAGE OverloadedStrings #-}
module Main where

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck.Monadic as QC
import Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Utils

import Crypto.TripleSec


main = defaultMain $ testGroup "triplesec" [katTests, knownFailures, properties]

katTests :: TestTree
katTests = testGroup "Decryption KATs" $ makeKatTestTree <$> zip kats [1..]

kats :: [(Password, PlainText, HexEncodedCipherText)]
kats = [ -- https://github.com/keybase/go-triplesec/blob/master/triplesec_test.go
         ("42", "ciao", "1c94d7de0000000359a5e5d60f09ebb6bc3fdab6642725e03bc3d51e167fa60327df567476d467f8b6ce65a909b4f582443f230ff10a36f60315ebce1cf1395d7b763c768764207f4f4cc5207a21272f3a5542f35db73c94fbc7bd551d4d6b0733e0b27fdf9606b8a26d45c4b79818791b6ae1ad34c23e58de482d454895618a1528ec722c5218650f8a2f55f63a6066ccf875f46c9b68ed31bc1ddce8881d704be597e1b5006d16ebe091a02e24d569f3d09b0578d12f955543e1a1f1dd75784b8b4cba7ca0bb7044389eb6354cea628a21538d")

         -- https://github.com/keybase/python-triplesec/blob/master/triplesec/test/vectors.json
       , (B.pack [0x74,0x68,0x69,0x73,0x20,0x62,0x65,0x20,0x74,0x68,0x65,0x20,0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64],"this be the secret message -> this be the secret message -> this be the secret message -> this be the secret message -> this be the secret message -> this be the secret message", "1c94d7de00000003bd202d905238954eab386b1c8500de93847378e0791793d0c31625f9a7cf7af6ed75abaa248edabe103408ce65a8ada16186a8d08982b82397b59250c7e40b4db3e0f3e4abd4a351fc71799dd23b2c2027d45a311019cc5bcdcbf1978b068e107f53d26aa92c0ff00707754f3e31084fc2a1923c2733f72eb6bafd88784eb8e8b9a30b9f9e049be390c8dd24981ccbeaa448198494c662db397ff561182c25a1c62b279984d4cf3528ddf9215aa1a7acbbc83a2ef868d902593491dd34bf397d06c3bbecafa9eaacd9861b4ffd54fd86d7a69369646a25d2ba12afb80ca43026fd146b1d018bbb8e93f4e5e35f7e10bfe5ba5c7ee3ae5828a47902e0abd6bfdd3599c752f59aa2a3076da38ebe33818c96d5df3476918ec5d218da3cda2aff760ccf4f28e8fe5cc55f50fc1b7abf58039425303d6da2de01a355fa3fc54d285cc194b53e53b82063e3ee0e6d04ef727fda6312986c53067341a33d89ff1fafcfe04688f3e4dea13604c6c2bc3ef7a0cd9e416ced1e2d1a25")
       , ("ANNA", "=)", "1c94d7de00000003d0c87b785a9daf6d25776df2d3f9a5d9a0b08e186ecebc2dc20c02a077ecde9e7a6f4cf705c45729d1dbd8f07acf94b6d756336265991b209ee94c57059699b06846506a043837463f594eb922660ee48f5c2a4de14ee4de70d5004668a84e396e2123a8a7de9fde35ccbcb58fdbb5b624cb67adfac29a9c0ccb67e09675da2bdf1cb47646822bfd5ac1e0887cc23e5e0c4866a9bdab3d4ab4ca394f7e1d0acb6697b477e1feae0d9faf1da42ef49f1a311e5ef7cbe2cf347d7e52d83fc18943cecfb0c310881799cff0")
       , (B.pack [0xaa,0xbb,0xcc,0xee], B.pack [0x11,0x00,0xaa,0xbb,0xee], "1c94d7de00000003b0c835fe415bd9534bbb614952d2b373367d8a0f664ee0d791152f632d15a9aadef9d4ba6cbc1db87d5cee3e5a26b3209f2a653e83eac1c05a9ad10d4b29b465db35326268231f4f085aa2b0977c2cd5a8a80a93bcd1dec495be59a01f79a2e6b14ca4088ebb2a617fee688b1b0765339eaf8719276270c4b2f3c5753fb273df5e257d6caddc026ffec7ab4df4e8a77d124f5cd7ef4b77e2daeb1affb47d5f249c3a7fd27fac639d6c43c648129176b6c664396d7c8130513be61a4028cdfe573012e36c91edf5b661e294d53c") ]

properties :: TestTree
properties = localOption (QuickCheckTests 10) $ testGroup "Properties"
  [ testProperty "encrypt password plaintext >>= decrypt password == return plaintext" $
      \(NonEmptyByteString plaintext, NonEmptyByteString password) -> monadicIO $ do
        cycledPlaintext <- run (decrypt password =<< encrypt password plaintext)
        QC.assert $ plaintext == cycledPlaintext,
    testProperty "encryptWithCipher cipher plaintext >>= decryptWithCipher cipher == return plaintext" $
      \(NonEmptyByteString plaintext, NonEmptyByteString password) -> monadicIO $ do
        cipher <- run (newCipher password)
        cycledPlaintext <- run (decryptWithCipher cipher =<< encryptWithCipher cipher plaintext)
        QC.assert $ plaintext == cycledPlaintext
       ]

knownFailures :: TestTree
knownFailures = testGroup "Known Failures"
  [ testCase "Test zero-length plaintext failure" $
      assertException ZeroLengthPlaintext (encrypt "password" "" :: IO ByteString),
    testCase "Test zero-length password failure" $
      assertException ZeroLengthPassword (encrypt "" "super secret message" :: IO ByteString),
    testCase "Test invalid salt length" $
      assertException InvalidSaltLength (newCipherWithSalt "password" "too-short" :: IO (TripleSec ByteString)),
    testCase "Test mismatched cipher failure" $
      assertException MisMatchedCipherSalt $ do
        let password = "password" :: ByteString
        cipherA <- newCipherWithSalt password (B.replicate 16 0xA :: ByteString)
        cipherB <- newCipherWithSalt password (B.replicate 16 0xB :: ByteString)
        encrypted <- encryptWithCipher cipherA "plaintext"
        _ <- decryptWithCipher cipherB encrypted
        return (),
    testCase "Test wrong decryption password" $
      assertException (DecryptionFailure InvalidSha512Hmac)
        (encrypt "password" "secret message" >>= decrypt "wrong passwrod" :: IO ByteString)]

