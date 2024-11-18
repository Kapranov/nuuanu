{-# LANGUAGE OverloadedStrings #-}

module Data.String.Conversions (main) where

-- A handy illustration of converting between String,
-- Text and ByteString in Haskell

import Data.ByteString            as B
import Data.ByteString.Lazy       as BL
import Data.Text                  as T
import Data.Text.Encoding         as T
import Data.Text.IO               as T
import Data.Text.Lazy             as TL
import Data.Text.Lazy.Encoding    as TL
import Data.Text.Lazy.IO          as TL
import Prelude                    as P

main :: IO ()
main = do
  P.putStrLn "from String"
  B.putStr    $ T.encodeUtf8 . T.pack                 $ "String to strict ByteString"
  BL.putStr   $ TL.encodeUtf8 . TL.pack               $ "String to lazy ByteString"
  T.putStrLn  $ T.pack                                  "String to strict Text"
  TL.putStrLn $ TL.pack                                 "String to lazy Text"

  P.putStrLn "\nfrom strict ByteString"
  P.putStrLn  $ T.unpack . T.decodeUtf8               $ "strict ByteString to String"
  BL.putStr   $ BL.fromChunks . return                $ "strict ByteString to lazy ByteString"
  T.putStrLn  $ T.decodeUtf8                            "strict ByteString to strict Text"
  TL.putStrLn $ TL.fromStrict . T.decodeUtf8          $ "strict ByteString to lazy Text"

  P.putStrLn "\nfrom lazy ByteString"
  P.putStrLn  $ TL.unpack . TL.decodeUtf8             $ "lazy ByteString to String"
  B.putStr    $ B.concat . BL.toChunks                $ "lazy ByteString to strict ByteString"
  T.putStrLn  $ T.decodeUtf8 . B.concat . BL.toChunks $ "lazy ByteString to strict Text"
  TL.putStrLn $ TL.decodeUtf8                           "lazy ByteString to lazy Text"

  P.putStrLn "\nfrom strict Text"
  P.putStrLn  $ T.unpack                                "strict Text to String"
  B.putStr    $ T.encodeUtf8                            "strict Text to strict ByteString"
  BL.putStr   $ BL.fromChunks . return . T.encodeUtf8 $ "strict Text to lazy ByteString"
  TL.putStrLn $ TL.fromStrict                           "strict Text to lazy Text"

  P.putStrLn "\nfrom lazy Text"
  P.putStrLn  $ TL.unpack                               "lazy Text to String"
  B.putStr    $ T.encodeUtf8 . TL.toStrict            $ "lazy Text to strict ByteString"
  BL.putStr   $ TL.encodeUtf8                           "lazy Text to lazy ByteString"
  T.putStrLn  $ TL.toStrict                             "lazy Text to strict Text"
