{-# LANGUAGE OverloadedStrings #-}

module Lib
    ( someFunc
    ) where

import qualified Data.Text.IO as T
import qualified Platform.HTTP as HTTP

someFunc :: IO ()
someFunc = do
  T.putStrLn "Kamehameha Schools offers land for new Lahaina site"
  HTTP.main
