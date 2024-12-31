{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-|
  Module     : Auth.Bisque.Example
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
-}
module Auth.Bisque.Example ( creation
                           , privateKey'
                           , publicKey'
                           , verification
                           ) where

import Auth.Bisque
import Data.ByteString (ByteString)
import Data.Functor    (($>))
import Data.Maybe      (fromMaybe)
import Data.Time       (getCurrentTime)

privateKey' :: SecretKey
privateKey' = fromMaybe (error "Error parsing private key") $ parseSecretKeyHex "todo"

publicKey' :: PublicKey
publicKey' = fromMaybe (error "Error parsing public key") $ parsePublicKeyHex "todo"

creation :: IO ByteString
creation = do
  let authority = [block|resource("file1");|]
  bisque <- mkBisque privateKey' authority
  let block1 = [block|check if current_time($time), $time < 2024-12-12T00:00:00Z;|]
  newBisque <- addBlock block1 bisque
  pure $ serializeB64 newBisque

verification :: ByteString -> IO Bool
verification serialized = do
  now <- getCurrentTime
  bisque <- either (fail . show) pure $ parseB64 publicKey' serialized
  let authorizer' = [authorizer|current_time(${now});|]
  result <- authorizeBisque bisque authorizer'
  case result of
    Left e  -> print e $> False
    Right _ -> pure True
