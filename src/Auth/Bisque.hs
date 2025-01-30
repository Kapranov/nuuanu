{-# LANGUAGE DataKinds                                       #-}
{-# LANGUAGE EmptyDataDeriving                               #-}
{-# OPTIONS_GHC -fno-warn-missing-pattern-synonym-signatures #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures                 #-}
{-|
  Module     : Auth.Bisque
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
-}
module Auth.Bisque (
                   -- * An authToken creating keypairs
                     PublicKey
                   , SecretKey
                   , newPublic
                   , newSecret
                   , toPublic
                   -- * Parsing and serializing keypairs
                   , parsePublicKey
                   , parsePublicKeyHex
                   , parseSecretKey
                   , parseSecretKeyHex
                   , serializePublicKey
                   , serializePublicKeyHex
                   , serializePublicKeyHex'
                   , serializeSecretKey
                   , serializeSecretKeyHex
                   , serializeSecretKeyHex'
                   -- * Creating a bisque
                   , Bisque
                   , BisqueProof
                   , Block
                   , Open
                   , OpenOrSealed
                   , Sealed
                   , Unverified
                   , Verified
                   , block
                   , blockContext
                   , mkBisque
                   , mkBisqueWith
                   -- * Parsing and serializing bisques
                   , BisqueEncoding (RawBytes, UrlBase64)
                   , ParserConfig (..)
                   , checkBisqueSignatures
                   , fromHex
                   , fromRevocationList
                   , parse
                   , parseB64
                   , parseBisqueWith
                   , parseWith
                   , serialize
                   , serializeB64
                   -- * Attenuating bisques
                   , addBlock
                   , asOpen
                   , asSealed
                   , fromOpen
                   , fromSealed
                   , seal
                   -- * Verifying a bisque
                   , AuthorizationSuccess (..)
                   , Authorizer
                   , ExecutionError (..)
                   , FromValue (..)
                   , Limits (..)
                   , MatchedQuery (..)
                   , ParseError (..)
                   , Term
                   , Term' (..)
                   , ToTerm (..)
                   , authorizeBisque
                   , authorizer
                   , defaultLimits
                   , getBindings
                   , getSingleVariableValue
                   , getVariableValues
                   , query
                   , queryAuthorizerFacts
                   -- * Retrieving information from a bisque
                   , encodeHex
                   , encodeHex'
                   , getRevocationIds
                   , getVerifiedBisquePublicKey
                   ) where

import Auth.Bisque.Crypto                   ( PublicKey
                                            , SecretKey
                                            , convert
                                            , generateSecretKey
                                            , maybeCryptoError
                                            , publicKey
                                            , secretKey
                                            , toPublic
                                            )
import Auth.Bisque.Datalog.AST              ( Authorizer
                                            , Block
                                            , FromValue (..)
                                            , Term
                                            , Term' (..)
                                            , ToTerm (..)
                                            , bContext
                                            )
import Auth.Bisque.Datalog.Executor         ( ExecutionError (..)
                                            , Limits (..)
                                            , MatchedQuery (..)
                                            , defaultLimits
                                            )
import Auth.Bisque.Datalog.Parser           ( authorizer
                                            , block
                                            , query
                                            )
import Auth.Bisque.Datalog.ScopedExecutor   ( AuthorizationSuccess (..)
                                            , getBindings
                                            , getSingleVariableValue
                                            , getVariableValues
                                            , queryAuthorizerFacts
                                            )
import Auth.Bisque.Token                    ( Bisque
                                            , BisqueEncoding (..)
                                            , BisqueProof (..)
                                            , Open
                                            , OpenOrSealed
                                            , ParseError (..)
                                            , ParserConfig (..)
                                            , Sealed
                                            , Unverified
                                            , Verified
                                            , addBlock
                                            , asOpen
                                            , asSealed
                                            , authorizeBisque
                                            , checkBisqueSignatures
                                            , fromOpen
                                            , fromSealed
                                            , getRevocationIds
                                            , getVerifiedBisquePublicKey
                                            , mkBisque
                                            , mkBisqueWith
                                            , parseBisqueWith
                                            , seal
                                            , serializeBisque
                                            )
import Auth.Bisque.Utils                    ( decodeHex
                                            , encodeHex
                                            , encodeHex'
                                            )
import Control.Monad                        ((<=<))
import Control.Monad.Identity               (runIdentity)
import Data.ByteString                      (ByteString)
import qualified Data.ByteString.Base64.URL as B64
import qualified Data.Text                  as T
import Data.Foldable                        (toList)
import Data.Set                             (Set)
import qualified Data.Set                   as Set

blockContext :: T.Text -> Block
blockContext c = mempty { bContext = Just c }

fromHex :: MonadFail m => ByteString -> m ByteString
fromHex = either (fail . T.unpack) pure . decodeHex

fromRevocationList :: (Applicative m, Foldable t) => t ByteString -> Set ByteString -> m Bool
fromRevocationList revokedIds tokenIds =
  pure . not . null $ Set.intersection (Set.fromList $ toList revokedIds) tokenIds

newPublic :: IO PublicKey
newPublic = do
  newSecretKey <- newSecret
  let genPublicKey = toPublic newSecretKey
  pure genPublicKey

newSecret :: IO SecretKey
newSecret = generateSecretKey

parse :: PublicKey -> ByteString -> Either ParseError (Bisque OpenOrSealed Verified)
parse pk = runIdentity . parseBisqueWith ParserConfig
  { encoding = RawBytes
  , isRevoked = const $ pure False
  , getPublicKey = pure pk
  }

parseB64 :: PublicKey -> ByteString -> Either ParseError (Bisque OpenOrSealed Verified)
parseB64 pk = runIdentity . parseBisqueWith ParserConfig
  { encoding = UrlBase64
  , isRevoked = const $ pure False
  , getPublicKey = pure pk
  }

parsePublicKey :: ByteString -> Maybe PublicKey
parsePublicKey = maybeCryptoError . publicKey

parsePublicKeyHex :: ByteString -> Maybe PublicKey
parsePublicKeyHex = parsePublicKey <=< fromHex

parseSecretKey :: ByteString -> Maybe SecretKey
parseSecretKey = maybeCryptoError . secretKey

parseSecretKeyHex :: ByteString -> Maybe SecretKey
parseSecretKeyHex = parseSecretKey <=< fromHex

parseWith :: Applicative m => ParserConfig m -> ByteString -> m (Either ParseError (Bisque OpenOrSealed Verified))
parseWith = parseBisqueWith

serialize :: BisqueProof p => Bisque p Verified -> ByteString
serialize = serializeBisque

serializeB64 :: BisqueProof p => Bisque p Verified -> ByteString
serializeB64 = B64.encode . serialize

serializePublicKey :: PublicKey -> ByteString
serializePublicKey = convert

serializePublicKeyHex :: PublicKey -> T.Text
serializePublicKeyHex = encodeHex . convert

serializePublicKeyHex' :: PublicKey -> ByteString
serializePublicKeyHex' = encodeHex' . convert

serializeSecretKey :: SecretKey -> ByteString
serializeSecretKey = convert

serializeSecretKeyHex :: SecretKey -> T.Text
serializeSecretKeyHex = encodeHex . convert

serializeSecretKeyHex' :: SecretKey -> ByteString
serializeSecretKeyHex' = encodeHex' . convert
