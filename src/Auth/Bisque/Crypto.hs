{-# LANGUAGE PackageImports #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
module Auth.Bisque.Crypto
  ( MyPublicKey
  , MySecretKey
  , MySignature
  , genSecretKey
  , pkBytes
  , readEd25519PublicKey
  , readEd25519SecretKey
  , skBytes
  , toPublish
  ) where

import "crypton" Crypto.PubKey.Ed25519 as Ed25519
import "crypton" Crypto.Error (maybeCryptoError)
import Data.ByteArray (convert)
import Data.ByteString (ByteString)

newtype MySecretKey = SecretKey Ed25519.SecretKey deriving newtype (Eq, Show)
newtype MyPublicKey = PublicKey Ed25519.PublicKey deriving newtype (Eq, Show)
newtype MySignature = Signature ByteString deriving newtype (Eq, Show)

readEd25519SecretKey :: ByteString -> Maybe MySecretKey
readEd25519SecretKey bs = SecretKey <$> maybeCryptoError (Ed25519.secretKey bs)

readEd25519PublicKey :: ByteString -> Maybe MyPublicKey
readEd25519PublicKey bs = PublicKey <$> maybeCryptoError (Ed25519.publicKey bs)

-- | Generate a public key from a secret key
toPublish :: MySecretKey -> MyPublicKey
toPublish (SecretKey sk) = PublicKey $ Ed25519.toPublic sk

genSecretKey :: IO MySecretKey
genSecretKey = SecretKey <$> Ed25519.generateSecretKey

pkBytes :: MyPublicKey -> ByteString
pkBytes (PublicKey pk) = convert pk

skBytes :: MySecretKey -> ByteString
skBytes (SecretKey sk) = convert sk
