{-# LANGUAGE OverloadedStrings #-}
module Auth.Bisque.Example ( publicKey'
                           , privateKey'
                           ) where

import Auth.Bisque     ( MyPublicKey
                       , MySecretKey
                       , parsePublicKeyHex
                       , parseSecretKeyHex
                       )
-- import Data.ByteString (ByteString)
-- import Data.Functor    (($>))
import Data.Maybe      (fromMaybe)
-- import Data.Text       (Text)
-- import Data.Time       (getCurrentTime)

publicKey' :: MyPublicKey
publicKey' = fromMaybe (error "Error parsing public key") $ parsePublicKeyHex "24afd8171d2c0107ec6d5656aa36f8409184c2567649e0a7f66e629cc3dbfd70"

privateKey' :: MySecretKey
privateKey' = fromMaybe (error "Error parsing private key") $ parseSecretKeyHex "a2c4ead323536b925f3488ee83e0888b79c2761405ca7c0c9a018c7c1905eecc"
