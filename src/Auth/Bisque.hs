{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE EmptyDataDeriving #-}
{-# OPTIONS_GHC -fno-warn-missing-pattern-synonym-signatures #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
module Auth.Bisque
  ( MyPublicKey
  , MySecretKey
  , fromHex
  , newSecret
  , parsePublicKey
  , parsePublicKeyHex
  , parseSecretKey
  , parseSecretKeyHex
  , serializePublicKey
  , serializePublicKeyHex
  , serializeSecretKey
  , serializeSecretKeyHex
  , toPublish
  ) where

import Auth.Bisque.Crypto  ( MyPublicKey
                           , MySecretKey
                           , genSecretKey
                           , pkBytes
                           , readEd25519PublicKey
                           , readEd25519SecretKey
                           , skBytes
                           , toPublish
                           )
import Auth.Bisque.Utils  (decodeHex, encodeHex')
import Control.Monad       ((<=<))
import Data.ByteString     (ByteString)
import qualified Data.Text as Text

newSecret :: IO MySecretKey
newSecret = genSecretKey

-- | Read a 'PublicKey' from an hex bytestring
parsePublicKeyHex :: ByteString -> Maybe MyPublicKey
parsePublicKeyHex = parsePublicKey <=< fromHex

-- | Read a 'SecretKey' from an hex bytestring
parseSecretKeyHex = parseSecretKey <=< fromHex

-- | Read a 'PublicKey' from raw bytes
parsePublicKey = readEd25519PublicKey

-- | Read a 'SecretKey' from raw bytes
parseSecretKey = readEd25519SecretKey

-- | Decode a base16-encoded bytestring, reporting errors via `MonadFail`
fromHex :: MonadFail m => ByteString -> m ByteString
fromHex = either (fail . Text.unpack) pure . decodeHex

-- | Serialize a 'PublicKey' to raw bytes, without any encoding
serializePublicKey :: MyPublicKey -> ByteString
serializePublicKey = pkBytes

-- | Serialize a 'SecretKey' to raw bytes, without any encoding
serializeSecretKey :: MySecretKey -> ByteString
serializeSecretKey = skBytes

-- | Serialize a 'PublicKey' to a hex-encoded bytestring
serializePublicKeyHex :: MyPublicKey -> ByteString
serializePublicKeyHex = encodeHex' . pkBytes

-- | Serialize a 'SecretKey' to a hex-encoded bytestring
serializeSecretKeyHex :: MySecretKey -> ByteString
serializeSecretKeyHex = encodeHex' . skBytes
