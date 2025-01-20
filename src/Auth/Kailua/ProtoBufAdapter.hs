{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TypeApplications  #-}
{-|
  Module      : Auth.Kailua.ProtoBufAdapter
  Copyright   : updated © Oleg G.Kapranov, 2025
  License     : MIT
  Maintainer  : lugatex@yahoo.com
  Conversion functions between biscuit components and protobuf-encoded components
-}
module Auth.Kailua.ProtoBufAdapter ( Symbols
                                   , blockToPb
                                   , buildSymbolTable
                                   , pbToBlock
                                   , pbToProof
                                   , pbToSignedBlock
                                   , pbToThirdPartyBlockContents
                                   , pbToThirdPartyBlockRequest
                                   , signedBlockToPb
                                   , thirdPartyBlockContentsToPb
                                   , thirdPartyBlockRequestToPb
                                   ) where

import qualified Auth.Kailua.Crypto      as Crypto
import           Auth.Kailua.Datalog.AST ( Binary (..)
                                         , Block
                                         , Block' (..)
                                         , Check
                                         , Check' (..)
                                         , CheckKind (..)
                                         , DatalogContext (..)
                                         , Expression
                                         , Fact
                                         , IsWithinSet (..)
                                         , Op (..)
                                         , Predicate
                                         , Predicate' (..)
                                         , PredicateOrFact (..)
                                         , QueryItem' (..)
                                         , Rule
                                         , Rule' (..)
                                         , RuleScope
                                         , RuleScope' (..)
                                         , Term
                                         , Term' (..)
                                         , Unary (..)
                                         , Value
                                         , fromStack
                                         , isCheckOne
                                         , listPublicKeysInBlock
                                         , listSymbolsInBlock
                                         , makeRule
                                         , queryHasNoScope
                                         , queryHasNoV4Operators
                                         , ruleHasNoScope
                                         , ruleHasNoV4Operators
                                         , toStack
                                         )
import qualified Auth.Kailua.Proto       as PB
import           Auth.Kailua.Symbols     ( BlockSymbols
                                         , PublicKeyRef (..)
                                         , ReverseSymbols
                                         , SymbolRef (..)
                                         , Symbols
                                         , addFromBlock
                                         , addSymbols
                                         , getPkList
                                         , getPublicKey'
                                         , getPublicKeyCode
                                         , getSymbol
                                         , getSymbolCode
                                         , getSymbolList
                                         , newSymbolTable
                                         , registerNewPublicKeys
                                         , registerNewSymbols
                                         , reverseSymbols
                                         )
import           Auth.Kailua.Utils       (maybeToRight)
import           Control.Monad           ( unless
                                         , when
                                         )
import           Control.Monad.State     ( StateT
                                         , get
                                         , lift
                                         , modify
                                         )
import           Data.ByteString         (ByteString)
import           Data.Int                (Int64)
import qualified Data.List.NonEmpty      as NE
import           Data.Maybe              ( isJust
                                         , isNothing
                                         )
import qualified Data.Set                as Set
import qualified Data.Text               as T
import           Data.Time               (UTCTime)
import           Data.Time.Clock.POSIX   ( posixSecondsToUTCTime
                                         , utcTimeToPOSIXSeconds
                                         )
import           Data.Void               (absurd)
import           GHC.Records             (getField)
import           Validation              (Validation (..))

pbToPublicKey :: PB.ExPublicKey -> Either String Crypto.PublicKey
pbToPublicKey PB.ExPublicKey{..} =
  let keyBytes = PB.getField key
      parseKey = Crypto.readEd25519PublicKey
  in case PB.getField algorithm of
       PB.Ed25519 -> maybeToRight "Invalid ed25519 public key" $ parseKey keyBytes

publicKeyToPb :: Crypto.PublicKey -> PB.ExPublicKey
publicKeyToPb pk = PB.ExPublicKey
  { algorithm = PB.putField PB.Ed25519
  , key = PB.putField $ Crypto.pkBytes pk
  }

pbToProof :: PB.Proof -> Either String (Either Crypto.Signature Crypto.SecretKey)
pbToProof (PB.ProofSignature rawSig) = Left  <$> Right (Crypto.signature $ PB.getField rawSig)
pbToProof (PB.ProofSecret    rawPk)  = Right <$> maybeToRight "Invalid public key proof" (Crypto.readEd25519SecretKey $ PB.getField rawPk)

pbTimeToUtcTime :: Int64 -> UTCTime
pbTimeToUtcTime = posixSecondsToUTCTime . fromIntegral

pbToSetValue :: Symbols -> PB.TermV2 -> Either String (Term' 'WithinSet 'InFact 'Representation)
pbToSetValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString  <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable _ -> Left "Variables can't appear in facts or sets"
  PB.TermTermSet  _ -> Left "Sets can't be nested"

pbToValue :: Symbols -> PB.TermV2 -> Either String Value
pbToValue s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable _ -> Left "Variables can't appear in facts"
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

pbToTerm :: Symbols -> PB.TermV2 -> Either String Term
pbToTerm s = \case
  PB.TermInteger  f -> pure $ LInteger $ fromIntegral $ PB.getField f
  PB.TermString   f ->        LString <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermDate     f -> pure $ LDate    $ pbTimeToUtcTime $ PB.getField f
  PB.TermBytes    f -> pure $ LBytes   $ PB.getField f
  PB.TermBool     f -> pure $ LBool    $ PB.getField f
  PB.TermVariable f -> Variable <$> getSymbol s (SymbolRef $ PB.getField f)
  PB.TermTermSet  f -> TermSet . Set.fromList <$> traverse (pbToSetValue s) (PB.getField . PB.set $ PB.getField f)

pbToUnary :: PB.OpUnary -> Unary
pbToUnary PB.OpUnary{kind} = case PB.getField kind of
  PB.Negate -> Negate
  PB.Parens -> Parens
  PB.Length -> Length

pbToBinary :: PB.OpBinary -> Binary
pbToBinary PB.OpBinary{kind} = case PB.getField kind of
  PB.LessThan       -> LessThan
  PB.GreaterThan    -> GreaterThan
  PB.LessOrEqual    -> LessOrEqual
  PB.GreaterOrEqual -> GreaterOrEqual
  PB.Equal          -> Equal
  PB.Contains       -> Contains
  PB.Prefix         -> Prefix
  PB.Suffix         -> Suffix
  PB.Regex          -> Regex
  PB.Add            -> Add
  PB.Sub            -> Sub
  PB.Mul            -> Mul
  PB.Div            -> Div
  PB.And            -> And
  PB.Or             -> Or
  PB.Intersection   -> Intersection
  PB.Union          -> Union
  PB.BitwiseAnd     -> BitwiseAnd
  PB.BitwiseOr      -> BitwiseOr
  PB.BitwiseXor     -> BitwiseXor
  PB.NotEqual       -> NotEqual

pbToOp :: Symbols -> PB.Op -> Either String Op
pbToOp s = \case
  PB.OpVValue v  -> VOp <$> pbToTerm s (PB.getField v)
  PB.OpVUnary v  -> pure . UOp . pbToUnary $ PB.getField v
  PB.OpVBinary v -> pure . BOp . pbToBinary $ PB.getField v

pbToPredicate :: Symbols -> PB.PredicateV2 -> Either String (Predicate' 'InPredicate 'Representation)
pbToPredicate s pbPredicate = do
  let pbName  = PB.getField $ PB.name  pbPredicate
      pbTerms = PB.getField $ PB.terms pbPredicate
  name <- getSymbol s $ SymbolRef pbName
  terms <- traverse (pbToTerm s) pbTerms
  pure Predicate{..}

pbToExpression :: Symbols -> PB.ExpressionV2 -> Either String Expression
pbToExpression s PB.ExpressionV2{ops} = do
  parsedOps <- traverse (pbToOp s) $ PB.getField ops
  fromStack parsedOps

pbToFact :: Symbols -> PB.FactV2 -> Either String Fact
pbToFact s PB.FactV2{predicate} = do
  let pbName  = PB.getField $ PB.name  $ PB.getField predicate
      pbTerms = PB.getField $ PB.terms $ PB.getField predicate
  name <- getSymbol s $ SymbolRef pbName
  terms <- traverse (pbToValue s) pbTerms
  pure Predicate{..}

pbToRule :: Symbols -> PB.RuleV2 -> Either String Rule
pbToRule s pbRule = do
  let pbHead = PB.getField $ PB.head pbRule
      pbBody = PB.getField $ PB.body pbRule
      pbExpressions = PB.getField $ PB.expressions pbRule
      pbScope = PB.getField $ getField @"scope" pbRule
  rhead       <- pbToPredicate s pbHead
  body        <- traverse (pbToPredicate s) pbBody
  expressions <- traverse (pbToExpression s) pbExpressions
  scope       <- Set.fromList <$> traverse (pbToScope s) pbScope
  case makeRule rhead body expressions scope of
    Failure vs -> Left $ "Unbound variables in rule: " <> T.unpack (T.intercalate ", " $ NE.toList vs)
    Success r  -> pure r

pbToCheck :: Symbols -> PB.CheckV2 -> Either String Check
pbToCheck s PB.CheckV2{queries,kind} = do
  let toCheck Rule{body,expressions,scope} = QueryItem{qBody = body, qExpressions = expressions, qScope = scope}
  rules <- traverse (pbToRule s) $ PB.getField queries
  let cQueries = toCheck <$> rules
  let cKind = case PB.getField kind of
        Just PB.All -> All
        Just PB.One -> One
        Nothing     -> One
  pure Check{..}

pbToScope :: Symbols -> PB.Scope -> Either String RuleScope
pbToScope s = \case
  PB.ScType e       -> case PB.getField e of
    PB.ScopeAuthority -> Right OnlyAuthority
    PB.ScopePrevious  -> Right Previous
  PB.ScBlock pkRef ->
    BlockId <$> getPublicKey' s (PublicKeyRef $ PB.getField pkRef)

pbToBlock :: Maybe Crypto.PublicKey -> PB.Block -> StateT Symbols (Either String) Block
pbToBlock ePk PB.Block{..} = do
  blockPks <- lift $ traverse pbToPublicKey $ PB.getField pksTable
  let blockSymbols = PB.getField symbols
  when (isNothing ePk) $ do
    modify (registerNewSymbols blockSymbols)
    modify (registerNewPublicKeys blockPks)
  currentSymbols <- get
  let symbolsForCurrentBlock =
        if isNothing ePk then currentSymbols
                         else registerNewPublicKeys blockPks $ registerNewSymbols blockSymbols newSymbolTable
  let bContext = PB.getField context
      bVersion = PB.getField version
  lift $ do
    let s = symbolsForCurrentBlock
    bFacts <- traverse (pbToFact s) $ PB.getField facts_v2
    bRules <- traverse (pbToRule s) $ PB.getField rules_v2
    bChecks <- traverse (pbToCheck s) $ PB.getField checks_v2
    bScope <- Set.fromList <$> traverse (pbToScope s) (PB.getField scope)
    let v5Plus = isJust ePk
        v4Plus = not $ and
          [ Set.null bScope
          , all ruleHasNoScope bRules
          , all (queryHasNoScope . cQueries) bChecks
          , all isCheckOne bChecks
          , all ruleHasNoV4Operators bRules
          , all (queryHasNoV4Operators . cQueries) bChecks
          ]
    case (bVersion, v4Plus, v5Plus) of
      (Just 5, _, _) -> pure Block {..}
      (Just 4, _, False) -> pure Block {..}
      (Just 4, _, True) ->
        Left "Biscuit v5 features are present, but the block version is 4."
      (Just 3, False, False) -> pure Block {..}
      (Just 3, True, False) ->
        Left "Biscuit v4 features are present, but the block version is 3."
      (Just 3, _, True) ->
        Left "Biscuit v5 features are present, but the block version is 3."
      _ ->
        Left $ "Unsupported biscuit version: " <> maybe "0" show bVersion <> ". Only versions 3 and 4 are supported"

setValueToPb :: ReverseSymbols -> Term' 'WithinSet 'InFact 'Representation -> PB.TermV2
setValueToPb s = \case
  LInteger  v -> PB.TermInteger $ PB.putField v
  LString   v -> PB.TermString  $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate     v -> PB.TermDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes    v -> PB.TermBytes   $ PB.putField v
  LBool     v -> PB.TermBool    $ PB.putField v
  TermSet   v -> absurd v
  Variable  v -> absurd v
  Antiquote v -> absurd v

termToPb :: ReverseSymbols -> Term -> PB.TermV2
termToPb s = \case
  Variable  n -> PB.TermVariable $ PB.putField $ getSymbolRef $ getSymbolCode s n
  LInteger  v -> PB.TermInteger  $ PB.putField v
  LString   v -> PB.TermString   $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate     v -> PB.TermDate     $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes    v -> PB.TermBytes    $ PB.putField v
  LBool     v -> PB.TermBool     $ PB.putField v
  TermSet  vs -> PB.TermTermSet  $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs
  Antiquote v -> absurd v

unaryToPb ::  Unary -> PB.OpUnary
unaryToPb = PB.OpUnary . PB.putField . \case
  Negate -> PB.Negate
  Parens -> PB.Parens
  Length -> PB.Length

binaryToPb :: Binary -> PB.OpBinary
binaryToPb = PB.OpBinary . PB.putField . \case
  LessThan       -> PB.LessThan
  GreaterThan    -> PB.GreaterThan
  LessOrEqual    -> PB.LessOrEqual
  GreaterOrEqual -> PB.GreaterOrEqual
  Equal          -> PB.Equal
  Contains       -> PB.Contains
  Prefix         -> PB.Prefix
  Suffix         -> PB.Suffix
  Regex          -> PB.Regex
  Add            -> PB.Add
  Sub            -> PB.Sub
  Mul            -> PB.Mul
  Div            -> PB.Div
  And            -> PB.And
  Or             -> PB.Or
  Intersection   -> PB.Intersection
  Union          -> PB.Union
  BitwiseAnd     -> PB.BitwiseAnd
  BitwiseOr      -> PB.BitwiseOr
  BitwiseXor     -> PB.BitwiseXor
  NotEqual       -> PB.NotEqual

valueToPb :: ReverseSymbols -> Value -> PB.TermV2
valueToPb s = \case
  LInteger  v -> PB.TermInteger $ PB.putField v
  LString   v -> PB.TermString  $ PB.putField $ getSymbolRef $ getSymbolCode s v
  LDate     v -> PB.TermDate    $ PB.putField $ round $ utcTimeToPOSIXSeconds v
  LBytes    v -> PB.TermBytes   $ PB.putField v
  LBool     v -> PB.TermBool    $ PB.putField v
  TermSet  vs -> PB.TermTermSet $ PB.putField $ PB.TermSet $ PB.putField $ setValueToPb s <$> Set.toList vs
  Variable  v -> absurd v
  Antiquote v -> absurd v

predicateToPb :: ReverseSymbols -> Predicate -> PB.PredicateV2
predicateToPb s Predicate{..} =
  PB.PredicateV2
    { name  = PB.putField $ getSymbolRef $ getSymbolCode s name
    , terms = PB.putField $ termToPb s <$> terms
    }

opToPb :: ReverseSymbols -> Op -> PB.Op
opToPb s = \case
  VOp t -> PB.OpVValue  $ PB.putField $ termToPb s t
  UOp o -> PB.OpVUnary  $ PB.putField $ unaryToPb o
  BOp o -> PB.OpVBinary $ PB.putField $ binaryToPb o

expressionToPb :: ReverseSymbols -> Expression -> PB.ExpressionV2
expressionToPb s e =
  let ops = opToPb s <$> toStack e
  in PB.ExpressionV2 { ops = PB.putField ops }

buildSymbolTable :: Symbols -> Block -> BlockSymbols
buildSymbolTable existingSymbols block =
  let allSymbols = listSymbolsInBlock block
      allKeys = listPublicKeysInBlock block
  in addSymbols existingSymbols allSymbols allKeys

factToPb :: ReverseSymbols -> Fact -> PB.FactV2
factToPb s Predicate{..} =
  let
      predicate = PB.PredicateV2
        { name  = PB.putField $ getSymbolRef $ getSymbolCode s name
        , terms = PB.putField $ valueToPb s <$> terms
        }
  in PB.FactV2{predicate = PB.putField predicate}

ruleToPb :: ReverseSymbols -> Rule -> PB.RuleV2
ruleToPb s Rule{..} =
  PB.RuleV2
    { head = PB.putField $ predicateToPb s rhead
    , body = PB.putField $ predicateToPb s <$> body
    , expressions = PB.putField $ expressionToPb s <$> expressions
    , scope = PB.putField $ scopeToPb s <$> Set.toList scope
    }

checkToPb :: ReverseSymbols -> Check -> PB.CheckV2
checkToPb s Check{..} =
  let dummyHead = Predicate "query" []
      toQuery QueryItem{..} =
        ruleToPb s $ Rule { rhead = dummyHead
                          , body = qBody
                          , expressions = qExpressions
                          , scope = qScope
                          }
      pbKind = case cKind of
        One -> Nothing
        All -> Just PB.All
  in PB.CheckV2 { queries = PB.putField $ toQuery <$> cQueries
                , kind = PB.putField pbKind
                }

scopeToPb :: ReverseSymbols -> RuleScope -> PB.Scope
scopeToPb s = \case
  OnlyAuthority -> PB.ScType $ PB.putField PB.ScopeAuthority
  Previous      -> PB.ScType $ PB.putField PB.ScopePrevious
  BlockId pk    -> PB.ScBlock $ PB.putField $ getPublicKeyCode s pk

blockToPb :: Bool -> Symbols -> Block -> (BlockSymbols, PB.Block)
blockToPb hasExternalPk existingSymbols b@Block{..} =
  let v4Plus = not $ and
        [Set.null bScope
        , all ruleHasNoScope bRules
        , all (queryHasNoScope . cQueries) bChecks
        , all isCheckOne bChecks
        , all ruleHasNoV4Operators bRules
        , all (queryHasNoV4Operators . cQueries) bChecks
        ]
      v5Plus = hasExternalPk
      bSymbols = buildSymbolTable existingSymbols b
      s = reverseSymbols $ addFromBlock existingSymbols bSymbols
      symbols   = PB.putField $ getSymbolList bSymbols
      context   = PB.putField bContext
      facts_v2  = PB.putField $ factToPb s <$> bFacts
      rules_v2  = PB.putField $ ruleToPb s <$> bRules
      checks_v2 = PB.putField $ checkToPb s <$> bChecks
      scope     = PB.putField $ scopeToPb s <$> Set.toList bScope
      pksTable   = PB.putField $ publicKeyToPb <$> getPkList bSymbols
      version   = PB.putField $ if | v5Plus    -> Just 5
                                   | v4Plus    -> Just 4
                                   | otherwise -> Just 3
  in (bSymbols, PB.Block {..})

pbToOptionalSignature :: PB.ExternalSig -> Either String (Crypto.Signature, Crypto.PublicKey)
pbToOptionalSignature PB.ExternalSig{..} = do
  let sig = Crypto.signature $ PB.getField signature
  pk  <- pbToPublicKey $ PB.getField publicKey
  pure (sig, pk)

pbToSignedBlock :: PB.SignedBlock -> Either String Crypto.SignedBlock
pbToSignedBlock PB.SignedBlock{..} = do
  let sig = Crypto.signature $ PB.getField signature
  mSig <- traverse pbToOptionalSignature $ PB.getField externalSig
  pk  <- pbToPublicKey $ PB.getField nextKey
  pure ( PB.getField block
       , sig
       , pk
       , mSig
       )

pbToThirdPartyBlockContents :: PB.ThirdPartyBlockContents -> Either String (ByteString, Crypto.Signature, Crypto.PublicKey)
pbToThirdPartyBlockContents PB.ThirdPartyBlockContents{payload,externalSig} = do
  (sig, pk) <- pbToOptionalSignature $ PB.getField externalSig
  pure ( PB.getField payload
       , sig
       , pk
       )

pbToThirdPartyBlockRequest :: PB.ThirdPartyBlockRequest -> Either String Crypto.PublicKey
pbToThirdPartyBlockRequest PB.ThirdPartyBlockRequest{previousPk, pkTable} = do
  unless (null $ PB.getField pkTable) $ Left "Public key table provided in third-party block request"
  pbToPublicKey $ PB.getField previousPk

externalSigToPb :: (Crypto.Signature, Crypto.PublicKey) -> PB.ExternalSig
externalSigToPb (sig, pk) = PB.ExternalSig
  { signature = PB.putField $ Crypto.sigBytes sig
  , publicKey = PB.putField $ publicKeyToPb pk
  }

signedBlockToPb :: Crypto.SignedBlock -> PB.SignedBlock
signedBlockToPb (block, sig, pk, eSig) = PB.SignedBlock
  { block = PB.putField block
  , signature = PB.putField $ Crypto.sigBytes sig
  , nextKey = PB.putField $ publicKeyToPb pk
  , externalSig = PB.putField $ externalSigToPb <$> eSig
  }

thirdPartyBlockContentsToPb :: (ByteString, Crypto.Signature, Crypto.PublicKey) -> PB.ThirdPartyBlockContents
thirdPartyBlockContentsToPb (payload, sig, pk) = PB.ThirdPartyBlockContents
  { PB.payload = PB.putField payload
  , PB.externalSig = PB.putField $ externalSigToPb (sig, pk)
  }

thirdPartyBlockRequestToPb :: Crypto.PublicKey -> PB.ThirdPartyBlockRequest
thirdPartyBlockRequestToPb previousPk = PB.ThirdPartyBlockRequest
  { previousPk = PB.putField $ publicKeyToPb previousPk
  , pkTable = PB.putField []
  }
