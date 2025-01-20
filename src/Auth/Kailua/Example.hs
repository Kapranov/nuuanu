{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Auth.Kailua.Example ( creation
                           , privateKey'
                           , publicKey'
                           , verification
                           ) where

import Auth.Kailua
import Data.ByteString (ByteString)
import Data.Functor    (($>))
import Data.Maybe      (fromMaybe)
import Data.Time       (getCurrentTime)

privateKey' :: SecretKey
privateKey' = fromMaybe (error "Error parsing private key") $ parseSecretKeyHex "a2c4ead323536b925f3488ee83e0888b79c2761405ca7c0c9a018c7c1905eecc"

publicKey' :: PublicKey
publicKey' = fromMaybe (error "Error parsing public key") $ parsePublicKeyHex "24afd8171d2c0107ec6d5656aa36f8409184c2567649e0a7f66e629cc3dbfd70"

creation :: IO ByteString
creation = do
  let authority = [block|resource("file1");|]
  kailua <- mkKailua privateKey' authority
  let block1 = [block|check if time($time), $time < 2025-05-08T00:00:00Z;|]
  newKailua <- addBlock block1 kailua
  pure $ serializeB64 newKailua

verification :: ByteString -> IO Bool
verification serialized = do
  now <- getCurrentTime
  kailua <- either (fail . show) pure $ parseB64 publicKey' serialized
  let authorizer' = [authorizer|current_time({now});|]
  result <- authorizeKailua kailua authorizer'
  case result of
    Left e  -> print e $> False
    Right _ -> pure True
