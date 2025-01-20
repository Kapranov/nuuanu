{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE EmptyDataDeriving #-}
{-|
  Module     : Auth.Kailua
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
-}
module Auth.Kailua (
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
                   , serializeSecretKey
                   , serializeSecretKeyHex
                   -- * Creating the kailua
                   , Block
                   , Kailua
                   , KailuaProof
                   , Open
                   , OpenOrSealed
                   , Sealed
                   , Unverified
                   , Verified
                   , block
                   , blockContext
                   , mkKailua
                   , mkKailuaWith
                   -- * Parsing and serializing kailua
                   , KailuaEncoding (RawBytes, UrlBase64)
                   , ParserConfig (..)
                   , checkKailuaSignatures
                   , fromHex
                   , fromRevocationList
                   , parse
                   , parseB64
                   , parseKailuaUnverified
                   , parseKailuaWith
                   , parseWith
                   , serialize
                   , serializeB64
                   -- * Attenuating kailua
                   , addBlock
                   , asOpen
                   , asSealed
                   , fromOpen
                   , fromSealed
                   , seal
                   -- * Third-party blocks
                   , addSignedBlock
                   , applyThirdPartyBlock
                   , applyThirdPartyBlockB64
                   , mkThirdPartyBlock
                   , mkThirdPartyBlockB64
                   , mkThirdPartyBlockReq
                   , mkThirdPartyBlockReqB64
                   -- * Verifying a kailua
                   , AuthorizationSuccess (..)
                   , AuthorizedKailua (..)
                   , Authorizer
                   , ExecutionError (..)
                   , FromValue (..)
                   , Limits (..)
                   , MatchedQuery (..)
                   , ParseError (..)
                   , Term
                   , Term' (..)
                   , ToTerm (..)
                   , authorizeKailua
                   , authorizeKailuaWithLimits
                   , authorizer
                   , defaultLimits
                   , getBindings
                   -- * Retrieving information from the kailua
                   , encodeHex'
                   , getRevocationIds
                   , getSingleVariableValue
                   , getVariableValues
                   , getVerifiedKailuaPublicKey
                   , query
                   , queryAuthorizerFacts
                   , queryRawKailuaFacts
                   ) where

import Auth.Kailua.Crypto                   ( PublicKey
                                            , SecretKey
                                            , generateSecretKey
                                            , pkBytes
                                            , readEd25519PublicKey
                                            , readEd25519SecretKey
                                            , skBytes
                                            , toPublic
                                            )
import Auth.Kailua.Datalog.AST              ( Authorizer
                                            , Block
                                            , FromValue (..)
                                            , Term
                                            , Term' (..)
                                            , ToTerm (..)
                                            , bContext
                                            )
import Auth.Kailua.Datalog.Executor         ( ExecutionError (..)
                                            , Limits (..)
                                            , MatchedQuery (..)
                                            , defaultLimits
                                            )
import Auth.Kailua.Datalog.Parser           ( authorizer
                                            , block
                                            , query
                                            )
import Auth.Kailua.Datalog.ScopedExecutor   ( AuthorizationSuccess (..)
                                            , getBindings
                                            , getSingleVariableValue
                                            , getVariableValues
                                            )
import Auth.Kailua.Token                    ( AuthorizedKailua (..)
                                            , Kailua
                                            , KailuaEncoding (..)
                                            , KailuaProof (..)
                                            , Open
                                            , OpenOrSealed
                                            , ParseError (..)
                                            , ParserConfig (..)
                                            , Sealed
                                            , Unverified
                                            , Verified
                                            , addBlock
                                            , addSignedBlock
                                            , applyThirdPartyBlock
                                            , asOpen
                                            , asSealed
                                            , authorizeKailua
                                            , authorizeKailuaWithLimits
                                            , checkKailuaSignatures
                                            , fromOpen
                                            , fromSealed
                                            , getRevocationIds
                                            , getVerifiedKailuaPublicKey
                                            , mkKailua
                                            , mkKailuaWith
                                            , mkThirdPartyBlock
                                            , mkThirdPartyBlockReq
                                            , parseKailuaUnverified
                                            , parseKailuaWith
                                            , queryAuthorizerFacts
                                            , queryRawKailuaFacts
                                            , seal
                                            , serializeKailua
                                            )
import Auth.Kailua.Utils                    ( decodeHex
                                            , encodeHex'
                                            )
import qualified Data.Text                  as Text
import Control.Monad                        ((<=<))
import Control.Monad.Identity               (runIdentity)
import Data.Bifunctor                       (first)
import Data.ByteString                      (ByteString)
import qualified Data.ByteString.Base64.URL as B64
import Data.Foldable                        (toList)
import Data.Set                             (Set)
import qualified Data.Set                   as Set
import Data.Text                            ( Text
                                            , unpack
                                            )
newPublic :: IO PublicKey
newPublic = do
  newSecretKey <- newSecret
  let genPublicKey = toPublic newSecretKey
  pure genPublicKey

blockContext :: Text -> Block
blockContext c = mempty { bContext = Just c }

fromHex :: MonadFail m => ByteString -> m ByteString
fromHex = either (fail . Text.unpack) pure . decodeHex

newSecret :: IO SecretKey
newSecret = generateSecretKey

serializeSecretKey :: SecretKey -> ByteString
serializeSecretKey = skBytes

serializePublicKey :: PublicKey -> ByteString
serializePublicKey = pkBytes

serializeSecretKeyHex :: SecretKey -> ByteString
serializeSecretKeyHex = encodeHex' . skBytes

serializePublicKeyHex :: PublicKey -> ByteString
serializePublicKeyHex = encodeHex' . pkBytes

parseSecretKey :: ByteString -> Maybe SecretKey
parseSecretKey = readEd25519SecretKey

parseSecretKeyHex :: ByteString -> Maybe SecretKey
parseSecretKeyHex = parseSecretKey <=< fromHex

parsePublicKey :: ByteString -> Maybe PublicKey
parsePublicKey = readEd25519PublicKey

parsePublicKeyHex :: ByteString -> Maybe PublicKey
parsePublicKeyHex = parsePublicKey <=< fromHex

parse :: PublicKey -> ByteString -> Either ParseError (Kailua OpenOrSealed Verified)
parse pk = runIdentity . parseKailuaWith ParserConfig
  { encoding = RawBytes
  , isRevoked = const $ pure False
  , getPublicKey = pure pk
  }

parseB64 :: PublicKey -> ByteString -> Either ParseError (Kailua OpenOrSealed Verified)
parseB64 pk = runIdentity . parseKailuaWith ParserConfig
  { encoding = UrlBase64
  , isRevoked = const $ pure False
  , getPublicKey = pure pk
  }

parseWith :: Applicative m => ParserConfig m -> ByteString -> m (Either ParseError (Kailua OpenOrSealed Verified))
parseWith = parseKailuaWith

fromRevocationList :: (Applicative m, Foldable t) => t ByteString -> Set ByteString -> m Bool
fromRevocationList revokedIds tokenIds =
  pure . not . null $ Set.intersection (Set.fromList $ toList revokedIds) tokenIds

serialize :: KailuaProof p => Kailua p Verified -> ByteString
serialize = serializeKailua

serializeB64 :: KailuaProof p => Kailua p Verified -> ByteString
serializeB64 = B64.encode . serialize

mkThirdPartyBlockReqB64 :: Kailua Open c -> ByteString
mkThirdPartyBlockReqB64 = B64.encode . mkThirdPartyBlockReq

mkThirdPartyBlockB64 :: SecretKey -> ByteString -> Block -> Either String ByteString
mkThirdPartyBlockB64 sk reqB64 b = do
  req <- first unpack $ decodeHex reqB64
  contents <- mkThirdPartyBlock sk req b
  pure $ encodeHex' contents

applyThirdPartyBlockB64 :: Kailua Open check -> ByteString -> Either String (IO (Kailua Open check))
applyThirdPartyBlockB64 b contentsB64 = do
  contents <- first unpack $ decodeHex contentsB64
  applyThirdPartyBlock b contents
