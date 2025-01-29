{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DeriveTraversable     #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE TypeApplications      #-}
{-# OPTIONS_GHC -fno-warn-orphans  #-}
module Spec.Auth.Kailua.SampleReader ( BlockDesc (..)
                                     , CheckSet (..)
                                     , FactSet (..)
                                     , RuleSet (..)
                                     , RustError
                                     , RustResult (..)
                                     , SampleFile (..)
                                     , TestCase (..)
                                     , ValidationR (..)
                                     , WorldDesc (..)
                                     , buildTokenToFile
                                     , checkResult
                                     , checkTokenBlocks
                                     , compareExecErrors
                                     , compareParseErrors
                                     , getAuthority
                                     , getB
                                     , getBlocks
                                     , getSpecs
                                     , mkTestCase
                                     , mkTestCaseFromKailua
                                     , processFailedValidation
                                     , processTestCase
                                     , processValidation
                                     , readKailua
                                     , readSamplesFile
                                     , runTests
                                     ) where

import Auth.Kailua
import Auth.Kailua.Datalog.AST          ( renderAuthorizer
                                        , renderBlock
                                        )
import Auth.Kailua.Datalog.Executor     (ResultError (..))
import Auth.Kailua.Token
import Auth.Kailua.Utils                (encodeHex)
import Spec.Auth.Kailua.Parser          ( parseAuthorizer
                                        , parseBlock
                                        )
import Control.Arrow                    ((&&&))
import Control.Lens                     ((^?))
import Control.Monad                    ( join
                                        , when
                                        )
import Data.Aeson
import Data.Aeson.Lens                  (key)
import Data.Aeson.Types                 (typeMismatch)
import Data.Bifunctor                   (Bifunctor (..))
import Data.ByteString                  (ByteString)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Lazy   as LBS
import Data.Foldable                    ( fold
                                        , traverse_
                                        )
import Data.List.NonEmpty               ( NonEmpty (..)
                                        , toList
                                        )
import Data.Map.Strict                  (Map)
import qualified Data.Map.Strict        as Map
import Data.Maybe                       (isJust)
import Data.Text                        ( Text
                                        , unpack
                                        )
import Data.Text.Encoding               ( decodeUtf8
                                        , encodeUtf8
                                        )
import GHC.Generics                     (Generic)
import GHC.Records                      (HasField (getField))
import Test.Tasty                       hiding (Timeout)
import Test.Tasty.HUnit

type RustError = Value

data SampleFile a
  = SampleFile
  { root_private_key :: SecretKey
  , root_public_key  :: PublicKey
  , testcases        :: [TestCase a]
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass (FromJSON, ToJSON)

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
    deriving anyclass (FromJSON, ToJSON)

data TestCase a
  = TestCase
  { title       :: String
  , filename    :: a
  , token       :: NonEmpty BlockDesc
  , validations :: Map String ValidationR
  }
  deriving stock (Eq, Show, Generic, Functor, Foldable, Traversable)
  deriving anyclass (FromJSON, ToJSON)

data BlockDesc
  = BlockDesc
  { symbols :: [Text]
  , code    :: Text
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

data FactSet
  = FactSet
  { origin :: [Maybe Integer]
  , facts  :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

data RuleSet
  = RuleSet
  { origin :: Maybe Integer
  , rules  :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

data CheckSet
  = CheckSet
  { origin :: Maybe Integer
  , checks :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

data WorldDesc
  =  WorldDesc
  { facts    :: [FactSet]
  , rules    :: [RuleSet]
  , checks   :: [CheckSet]
  , policies :: [Text]
  }
  deriving stock (Eq, Show, Generic)
  deriving anyclass (FromJSON, ToJSON)

instance FromJSON SecretKey where
  parseJSON = withText "Ed25519 secret key" $ \t -> do
    let bs = encodeUtf8 t
        res = parseSecretKeyHex bs
        notSk = typeMismatch "Ed25519 secret key" (String t)
    maybe notSk pure res

instance ToJSON SecretKey where
  toJSON = toJSON . decodeUtf8 . serializeSecretKeyHex

instance FromJSON PublicKey where
  parseJSON = withText "Ed25519 public key" $ \t -> do
    let bs = encodeUtf8 t
        res = parsePublicKeyHex bs
        notPk = typeMismatch "Ed25519 public key" (String t)
    maybe notPk pure res

instance ToJSON PublicKey where
  toJSON = toJSON . decodeUtf8 . serializePublicKeyHex

instance FromJSON Authorizer where
  parseJSON = withText "authorizer" $ \t -> do
    let res = parseAuthorizer t
        notAuthorizer e = typeMismatch e (String t)
    either notAuthorizer pure res

instance ToJSON Authorizer where
  toJSON = toJSON . renderAuthorizer

instance Bifunctor RustResult where
  bimap f g = \case
    Err e -> Err $ f e
    Ok  a -> Ok $ g a

instance (FromJSON e, FromJSON a) => FromJSON (RustResult e a) where
   parseJSON = genericParseJSON $
     defaultOptions { sumEncoding = ObjectWithSingleField }

instance (ToJSON e, ToJSON a) => ToJSON (RustResult e a) where
   toJSON = genericToJSON $
     defaultOptions { sumEncoding = ObjectWithSingleField }

instance Semigroup WorldDesc where
  a <> b = WorldDesc
    { facts = getField @"facts" a <> getField @"facts" b
    , rules = getField @"rules" a <> getField @"rules" b
    , checks = getField @"checks" a <> getField @"checks" b
    , policies = policies a <> policies b
    }

instance Monoid WorldDesc where
  mempty = WorldDesc [] [] [] []

getB :: ParsedSignedBlock -> Block
getB ((_, b), _, _, _) = b

getBlocks :: Kailua p Verified -> [Block]
getBlocks = fmap getB . blocks

compareParseErrors :: ParseError -> RustError -> Assertion
compareParseErrors pe re =
  let mustMatch p = assertBool (show (re,pe)) $ isJust $ re ^? p
      mustMatchEither ps = assertBool (show (re, pe)) $ any (isJust . (re ^?)) ps
  in case pe of
       InvalidHexEncoding ->
         assertFailure $ "InvalidHexEncoding can't appear here " <> show re
       InvalidB64Encoding ->
         mustMatch $ key "Base64"
       InvalidProtobufSer True _ ->
         mustMatch $ key "Format" . key "DeserializationError"
       InvalidProtobuf True _ ->
         mustMatch $ key "Format" . key "DeserializationError"
       InvalidProtobufSer False _ ->
         mustMatch $ key "Format" . key "BlockDeserializationError"
       InvalidProtobuf False _ ->
         mustMatch $ key "Format" . key "BlockDeserializationError"
       InvalidSignatures ->
         mustMatchEither
           [ key "Format" . key "Signature" . key "InvalidSignature"
           , key "Format" . key "InvalidSignatureSize"
           ]
       InvalidProof ->
         assertFailure $ "InvalidProof can't appear here " <> show re
       RevokedKailua ->
         assertFailure $ "RevokedKailua can't appear here " <> show re

compareExecErrors :: ExecutionError -> RustError -> Assertion
compareExecErrors ee re =
  let errorMessage = "ExecutionError mismatch: " <> show ee <> " " <> unpack (decodeUtf8 . LBS.toStrict $ encode re)
      mustMatch p = assertBool errorMessage $ isJust $ re ^? p
  in case ee of
       Timeout                           -> mustMatch $ key "RunLimit"    . key "Timeout"
       TooManyFacts                      -> mustMatch $ key "RunLimit"    . key "TooManyFacts"
       TooManyIterations                 -> mustMatch $ key "RunLimit"    . key "TooManyIterations"
       InvalidRule                       -> mustMatch $ key "FailedLogic" . key "InvalidBlockRule"
       EvaluationError _                 -> mustMatch $ key "Execution"
       ResultError (NoPoliciesMatched _) -> mustMatch $ key "FailedLogic" . key "Unauthorized"
       ResultError (FailedChecks _)      -> mustMatch $ key "FailedLogic" . key "Unauthorized"
       ResultError (DenyRuleMatched _ _) -> mustMatch $ key "FailedLogic" . key "Unauthorized"

checkResult :: Show a => (a -> RustError -> Assertion) -> RustResult RustError Int -> Either a b -> Assertion
checkResult f r e = case (r, e) of
  (Err err, Right _) -> assertFailure $ "Got success, but expected failure: " <> show err
  (Ok    _, Left ss) -> assertFailure $ "Expected success, but got failure: " <> show ss
  (Err  er, Left ea) -> f ea er
  _ -> pure ()

processFailedValidation :: (String -> IO ()) -> ParseError -> (String, ValidationR) -> Assertion
processFailedValidation step e (name, ValidationR{result}) = do
  step $ "Checking validation " <> name
  checkResult compareParseErrors result (Left e)

getAuthority :: Kailua p Verified -> Block
getAuthority = getB . authority

checkTokenBlocks :: (String -> IO ()) -> Kailua OpenOrSealed Verified -> NonEmpty BlockDesc -> Assertion
checkTokenBlocks step b blockDescs = do
  step "Checking blocks"
  let bs = getAuthority b :| getBlocks b
      expected = traverse (parseBlock . code) blockDescs
  expected @?= Right bs

processValidation :: (String -> IO ()) -> Kailua OpenOrSealed Verified -> (String, ValidationR) -> Assertion
processValidation step b (name, ValidationR{..}) = do
  when (name /= "") $ step ("Checking " <> name)
  let w = fold world
  pols <- either (assertFailure . show) pure $ parseAuthorizer $ foldMap (<> ";") (policies w)
  res <- authorizeKailua b (authorizer_code <> pols)
  checkResult compareExecErrors result res
  let revocationIds = encodeHex <$> toList (getRevocationIds b)
  step "Comparing revocation ids"
  revocation_ids @?= revocationIds

processTestCase :: (String -> IO ()) -> PublicKey -> TestCase (FilePath, ByteString) -> Assertion
processTestCase step rootPk TestCase{..} =
  if fst filename == "test018_unbound_variables_in_rule.bc"
  then
    step "Skipping for now (unbound variables are now caught before evaluation)"
  else do
    step "Parsing "
    let vList = Map.toList validations
    case parse rootPk (snd filename) of
      Left parseError -> traverse_ (processFailedValidation step parseError) vList
      Right kailua    -> do
        checkTokenBlocks step kailua token
        traverse_ (processValidation step kailua) vList

readKailua :: SampleFile FilePath -> IO (SampleFile (FilePath, ByteString))
readKailua =
  traverse $ traverse (BS.readFile . ("test/samples/current/" <>)) . join (&&&) id

readSamplesFile :: IO (SampleFile (FilePath, ByteString))
readSamplesFile = do
  f <- either fail pure =<< eitherDecodeFileStrict' "test/samples/current/samples.json"
  readKailua f

mkTestCase :: PublicKey -> TestCase (FilePath, ByteString) -> TestTree
mkTestCase root_public_key tc@TestCase{filename} =
  testCaseSteps (fst filename) (\step -> processTestCase step root_public_key tc)

getSpecs :: IO TestTree
getSpecs = do
  SampleFile{..} <- readSamplesFile
  pure $ testGroup "Kailua samples - compliance checks"
       $ mkTestCase root_public_key <$> testcases

runTests :: (String -> IO ()) -> Assertion
runTests step = do
  step "Parsing sample file"
  SampleFile{..} <- readSamplesFile
  traverse_ (processTestCase step root_public_key) testcases

-- | Usage: create token and save to file for testing
-- >>> filename = "test031_limit_expired_token.bc" :: String
-- >>> sample <- readSamplesFile
-- >>> SampleFile {root_private_key = sk, root_public_key = pk, testcases = } = sample
-- >>> token <- buildToken sk "123"
-- >>> BS.writeFile ("test/samples/current/" <> filename) (serialize token)
-- >>> token <- BS.readFile ("test/samples/current/" <> filename)
-- >>> parsingOptions = ParserConfig {encoding = RawBytes, isRevoked = const $ pure False, getPublicKey = pure pk}
-- >>> parseWith parsingOptions token
-- |
buildTokenToFile :: SecretKey -> Text -> IO (Kailua Open Verified)
buildTokenToFile sk value = do
  -- TestCase 'test029_expired_token.bc'
  -- let authority = [block||]
  -- let block1 = [block|check if resource("file1");check if time($time), $time <= 2018-12-20T00:00:00Z;|]
  -- TestCase 'test030_period_has_expired.bc'
  -- let authority = [block||]
  -- let block1 = [block|check if user_id({value});check if time($0), $0 <= 2025-01-22T09:23:12+00:00;|]
  -- TestCase 'test031_limit_expired_token.bc'
  let authority = [block|user_id({value});check if time($0),$0 < 2025-12-31T00:00:00+00:00;|]
  let block1 = [block|check if user_id({value});check if time($0), $0 <= 2025-01-22T09:23:12+00:00;|]
  token <- mkKailua sk authority
  newKailua <- addBlock block1 token
  pure newKailua

mkTestCaseFromKailua :: String -> FilePath -> Kailua Open Verified -> [(String, Authorizer)] -> IO (TestCase FilePath)
mkTestCaseFromKailua title filename kailua authorizers = do
  let mkBlockDesc :: Block -> BlockDesc
      mkBlockDesc b = BlockDesc
        { code = renderBlock b
        , symbols = []
        }
      mkValidation :: Authorizer -> IO ValidationR
      mkValidation authorized = do
        Right _success <- authorizeKailua kailua authorized
        pure ValidationR
          { world = Just mempty
          , result = Ok 0
          , authorizer_code = authorized
          , revocation_ids = encodeHex <$> toList (getRevocationIds kailua)
          }
  BS.writeFile ("test/samples/current/" <> filename) (serialize kailua)
  let token = mkBlockDesc <$> getAuthority kailua :| getBlocks kailua
  validations <- Map.fromList <$> traverse (traverse mkValidation) authorizers
  pure TestCase{..}
