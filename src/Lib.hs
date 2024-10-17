{-# LANGUAGE OverloadedStrings #-}

module Lib
    ( someFunc
    ) where

import qualified Data.Text as T
import qualified Data.Text.IO as I
import qualified Platform.HTTP as HTTP

import System.Environment (lookupEnv)
import Data.Maybe (fromMaybe)

someFunc :: IO ()
someFunc = do
  I.putStrLn "Kamehameha Schools offers land for new Lahaina site"
  run

envPort :: String
envPort = "8080"

lookupPort :: IO Int
lookupPort = do
  portStr <- fromMaybe envPort <$> lookupEnv "PORT"
  return (read portStr :: Int)

welcome :: String
welcome = "Starting Web Server - http://localhost:"

run :: IO ()
run = do
  port <- lookupPort
  let msg = welcome <> (show port :: String)
  I.putStrLn (T.pack msg)
  HTTP.start port
