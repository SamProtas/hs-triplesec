{-# LANGUAGE OverloadedStrings #-}
module Main where

import Test.DocTest

main :: IO ()
main = doctest ["-XOverloadedStrings", "-XScopedTypeVariables", "-isrc", "src/Crypto/TripleSec/Tutorial.hs"]
