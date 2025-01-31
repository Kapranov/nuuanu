{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DeriveTraversable     #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}
module Spec.Auth.Bisque.SampleReader ( getSpecs
                                     , runTests
                                     , specs
                                     ) where

import Auth.Bisque                             ( Authorizer
                                               , Block
                                               , PublicKey
                                               , SecretKey
                                               , encodeHex
                                               , parse
                                               , parsePublicKeyHex
                                               , parseSecretKeyHex
                                               )
import Auth.Bisque.Datalog.Executor            ( ExecutionError (..)
                                               , ResultError (..)
                                               )
import Auth.Bisque.Datalog.Parser              ( authorizerParser
                                               , blockParser
                                               )
import Auth.Bisque.Token                       ( Bisque
                                               , OpenOrSealed
                                               , ParseError (..)
                                               , ParsedSignedBlock
                                               , Verified
                                               , authority
                                               , authorizeBisque
                                               , blocks
                                               , getRevocationIds
                                               )
import           Control.Arrow                 ((&&&))
import           Control.Lens                  ((^?))
import           Control.Monad                 (join, when)
import           Data.Aeson
import           Data.Aeson.Lens               (key)
import           Data.Aeson.Types              (typeMismatch)
import           Data.Attoparsec.Text          (parseOnly)
import           Data.Bifunctor                (Bifunctor (..))
import           Data.ByteString               (ByteString)
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Lazy          as LBS
import           Data.Foldable                 (traverse_)
import           Data.List.NonEmpty            (NonEmpty (..), toList)
import           Data.Map.Strict               (Map)
import qualified Data.Map.Strict               as Map
import           Data.Maybe                    (isJust)
import           Data.Text                     (Text, unpack)
import           Data.Text.Encoding            (decodeUtf8, encodeUtf8)
import           GHC.Generics                  (Generic)
import           Test.Tasty                    hiding (Timeout)
import           Test.Tasty.HUnit

type RustError = Value

data SampleFile a
  = SampleFile
  { root_private_key :: SecretKey
  , root_public_key  :: PublicKey
  , testcases        :: [TestCase a]
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass FromJSON

data RustResult e a
  = Err e
  | Ok a
  deriving stock (Generic, Eq, Show, Functor)

data ValidationR
  = ValidationR
  { world           :: Maybe WorldDesc
  , result          :: RustResult RustError Int
  , authorizer_code :: Authorizer
  , revocation_ids  :: [Text]
  } deriving stock (Eq, Show, Generic)
    deriving anyclass FromJSON

data TestCase a
  = TestCase
  { title       :: String
  , filename    :: a
  , token       :: NonEmpty BlockDesc
  , validations :: Map String ValidationR
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass FromJSON

data BlockDesc
  = BlockDesc
  { symbols :: [Text]
  , code    :: Text
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass FromJSON

data WorldDesc
  =  WorldDesc
  { facts    :: [Text]
  , rules    :: [Text]
  , checks   :: [Text]
  , policies :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass FromJSON

instance FromJSON SecretKey
  where
    parseJSON = withText "Ed25519 secret key" $ \t -> do
      let bs = encodeUtf8 t
          res = parseSecretKeyHex bs
          notSk = typeMismatch "Ed25519 secret key" (String t)
      maybe notSk pure res

instance FromJSON PublicKey
  where
    parseJSON = withText "Ed25519 public key" $ \t -> do
      let bs = encodeUtf8 t
          res = parsePublicKeyHex bs
          notPk = typeMismatch "Ed25519 public key" (String t)
      maybe notPk pure res

instance FromJSON Authorizer
  where
    parseJSON = withText "authorizer" $ \t -> do
      let res = parseAuthorizer t
          notAuthorizer e = typeMismatch e (String t)
      either notAuthorizer pure res

instance Bifunctor RustResult
  where
    bimap f g = \case
      Err e -> Err $ f e
      Ok  a -> Ok $ g a

instance (FromJSON e, FromJSON a) => FromJSON (RustResult e a) where
   parseJSON = genericParseJSON $
     defaultOptions { sumEncoding = ObjectWithSingleField }

instance (ToJSON e, ToJSON a) => ToJSON (RustResult e a) where
   toJSON = genericToJSON $
     defaultOptions { sumEncoding = ObjectWithSingleField }

parseAuthorizer :: Text -> Either String Authorizer
parseAuthorizer = parseOnly authorizerParser

getB :: ParsedSignedBlock -> Block
getB ((_, b), _, _) = b

getAuthority :: Bisque OpenOrSealed Verified -> Block
getAuthority = getB . authority

getBlocks :: Bisque OpenOrSealed Verified -> [Block]
getBlocks = fmap getB . blocks

parseBlock :: Text -> Either String Block
parseBlock = parseOnly blockParser

checkTokenBlocks :: (String -> IO ()) -> Bisque OpenOrSealed Verified -> NonEmpty BlockDesc -> Assertion
checkTokenBlocks step b blockDescs = do
  step "Checking blocks"
  let bs = getAuthority b :| getBlocks b
      expected = traverse (parseBlock . code) blockDescs
  expected @?= Right bs

checkResult :: Show a => (a -> RustError -> Assertion) -> RustResult RustError Int -> Either a b -> Assertion
checkResult f r e = case (r, e) of
  (Err es, Right _) -> assertFailure $ "Got success, but expected failure: " <> show es
  (Ok   _, Left  et) -> assertFailure $ "Expected success, but got failure: " <> show et
  (Err ex, Left ey) -> f ey ex
  _ -> pure ()

compareParseErrors :: ParseError -> RustError -> Assertion
compareParseErrors pe re =
  let mustMatch p = assertBool (show re) $ isJust $ re ^? p
  in case pe of
      InvalidHexEncoding ->
        assertFailure $ "InvalidHexEncoding can't appear here " <> show re
      InvalidB64Encoding ->
        mustMatch $ key "Base64"
      InvalidProtobufSer True _ ->
        mustMatch $ key "Format" . key "SerializationError"
      InvalidProtobufSer False _ ->
        mustMatch $ key "Format" . key "BlockSerializationError"
      InvalidProtobuf True "Invalid signature" ->
        mustMatch $ key "Format" . key "InvalidSignatureSize"
      InvalidProtobuf True _ ->
        mustMatch $ key "Format" . key "DeserializationError"
      InvalidProtobuf False _ ->
        mustMatch $ key "Format" . key "BlockDeserializationError"
      InvalidSignatures ->
        mustMatch $ key "Format" . key "Signature" . key "InvalidSignature"
      InvalidProof ->
        assertFailure $ "InvalidProof can't appear here " <> show re
      RevokedBisque ->
        assertFailure $ "RevokedBisque can't appear here " <> show re

processFailedValidation :: (String -> IO ()) -> ParseError -> (String, ValidationR) -> Assertion
processFailedValidation step e (name, ValidationR{result}) = do
  step $ "Checking validation " <> name
  checkResult compareParseErrors result (Left e)

compareExecErrors :: ExecutionError -> RustError -> Assertion
compareExecErrors ee re =
  let errorMessage = "ExecutionError mismatch: " <> show ee <> " " <> unpack (decodeUtf8 . LBS.toStrict $ encode re)
      mustMatch p = assertBool errorMessage $ isJust $ re ^? p
  in case ee of
      Timeout                           -> mustMatch $ key "RunLimit" . key "Timeout"
      TooManyFacts                      -> mustMatch $ key "RunLimit" . key "TooManyFacts"
      TooManyIterations                 -> mustMatch $ key "RunLimit" . key "TooManyIterations"
      InvalidRule                       -> mustMatch $ key "FailedLogic" . key "InvalidBlockRule"
      ResultError (NoPoliciesMatched _) -> mustMatch $ key "FailedLogic" . key "Unauthorized"
      ResultError (FailedChecks _)      -> mustMatch $ key "FailedLogic" . key "Unauthorized"
      ResultError (DenyRuleMatched _ _) -> mustMatch $ key "FailedLogic" . key "Unauthorized"

processValidation :: (String -> IO ()) -> Bisque OpenOrSealed Verified -> (String, ValidationR) -> Assertion
processValidation step b (name, ValidationR{..}) = do
  when (name /= "") $ step ("Checking " <> name)
  w    <- maybe (assertFailure "missing authorizer contents") pure world
  pols <- either (assertFailure . show) pure $ parseAuthorizer $ foldMap (<> ";") (policies w)
  res <- authorizeBisque b (authorizer_code <> pols)
  checkResult compareExecErrors result res
  let revocationIds = encodeHex <$> toList (getRevocationIds b)
  step "Comparing revocation ids"
  revocation_ids @?= revocationIds

processTestCase :: (String -> IO ()) -> PublicKey -> TestCase (FilePath, ByteString) -> Assertion
processTestCase step rootPk TestCase{..} = do
  step "Parsing "
  let vList = Map.toList validations
  case parse rootPk (snd filename) of
    Left parseError -> traverse_ (processFailedValidation step parseError) vList
    Right bisque    -> do
      checkTokenBlocks step bisque token
      traverse_ (processValidation step bisque) vList

readBisque :: SampleFile FilePath -> IO (SampleFile (FilePath, ByteString))
readBisque =
   traverse $ traverse (BS.readFile . ("test/samples/current/v1/" <>)) . join (&&&) id

readSamplesFile :: IO (SampleFile (FilePath, ByteString))
readSamplesFile = do
  Just f <- decodeFileStrict' "test/samples/current/v1/samples.json"
  readBisque f

runTests :: (String -> IO ()) -> Assertion
runTests step = do
  step "Parsing sample file"
  SampleFile{..} <- readSamplesFile
  traverse_ (processTestCase step root_public_key) testcases

specs :: TestTree
specs = testCaseSteps "Bisque samples - compliance checks" runTests

mkTestCase :: PublicKey -> TestCase (FilePath, ByteString) -> TestTree
mkTestCase root_public_key tc@TestCase{filename} =
  testCaseSteps (fst filename) (\step -> processTestCase step root_public_key tc)

getSpecs :: IO TestTree
getSpecs = do
  SampleFile{..} <- readSamplesFile
  pure $ testGroup "Bisque samples - compliance checks"
       $ mkTestCase root_public_key <$> testcases
