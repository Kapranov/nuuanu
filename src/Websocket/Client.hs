{-# LANGUAGE OverloadedStrings #-}

module Websocket.Client ( main ) where

import           Control.Concurrent  (forkIO)
import           Control.Monad       (forever, unless)
import           Control.Monad.Trans (liftIO)
import           Data.Text           (Text)
import           Network.Socket      (withSocketsDo)
import qualified Data.Text           as T
import qualified Data.Text.IO        as T
import qualified Network.WebSockets  as WS
-- import qualified Wuss                as WSS (runSecureClient)

app :: WS.ClientApp ()
app conn = do
  putStrLn "Connected!"
  _ <- forkIO $ forever $ do
    msg <- WS.receiveData conn
    liftIO $ T.putStrLn msg

  let loop = do
        line <- T.getLine
        unless (T.null line) $ WS.sendTextData conn line >> loop

  loop
  WS.sendClose conn ("Bye!" :: Text)

main :: IO ()
main = withSocketsDo $ WS.runClient "echo.websocket.org" 80 "/" app
-- main = withSocketsDo $ WSS.runSecureClient "api2.poloniex.com" 443 "/" app
