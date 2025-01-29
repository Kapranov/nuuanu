{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}
module Spec.Auth.Kailua.Verification (specs) where

import Auth.Kailua ( AuthorizationSuccess (..)
                   , AuthorizedKailua (..)
                   , ExecutionError (..)
                   , addBlock
                   , authorizeKailua
                   , authorizer
                   , block
                   , mkKailua
                   , newSecret
                   , query
                   )
import Auth.Kailua.Datalog.AST                ( Block' (..)
                                              , Check
                                              , Check' (..)
                                              , CheckKind (..)
                                              , Predicate' (..)
                                              , Rule' (..)
                                              , Term' (..)
                                              )
import Auth.Kailua.Datalog.Executor           ( MatchedQuery (..)
                                              , ResultError (..)
                                              )
import qualified Auth.Kailua.Datalog.Executor as Executor
import Auth.Kailua.Datalog.Parser             (check)
import Data.List.NonEmpty                     (NonEmpty ((:|)))
import qualified Data.Set                     as Set
import Test.Tasty
import Test.Tasty.HUnit

ifTrue :: MatchedQuery
ifTrue = MatchedQuery
  { matchedQuery = [query|true|]
  , bindings = Set.singleton mempty
  }

ifFalse :: MatchedQuery
ifFalse = MatchedQuery
  { matchedQuery = [query|false|]
  , bindings = Set.singleton mempty
  }

ifFalse' :: Check
ifFalse' = Check
  { cQueries = matchedQuery ifFalse
  , cKind = One
  }

specs :: TestTree
specs = testGroup "Datalog checks"
  [ singleBlock
  , checkAll
  , errorAccumulation
  , unboundVarRule
  , symbolRestrictions
  ]

singleBlock :: TestTree
singleBlock = testCase "Single block" $ do
  secret <- newSecret
  kailua <- mkKailua secret [block|right("file1", "read");|]
  res <- authorizeKailua kailua [authorizer|check if right("file1", "read");allow if true;|]
  matchedAllowQuery . authorizationSuccess <$> res @?= Right ifTrue

checkAll' :: Check
checkAll' = [check|check all fact($value), $value|]

checkAll :: TestTree
checkAll = testCase "Check all" $ do
  secret <- newSecret
  kailua <- mkKailua secret [block|fact(true); fact(false);|]
  res <- authorizeKailua kailua [authorizer|check all fact($value), $value;allow if true;|]
  res @?= Left (ResultError $ FailedChecks $ pure checkAll')

errorAccumulation :: TestTree
errorAccumulation = testGroup "Error accumulation"
  [ testCase "Only checks" $ do
      secret <- newSecret
      kailua <- mkKailua secret[block|check if false; check if false;|]
      res <- authorizeKailua kailua [authorizer|allow if true;|]
      res @?= Left (ResultError $ FailedChecks $ ifFalse' :| [ifFalse'])
  , testCase "Checks and deny policies" $ do
      secret <- newSecret
      kailua <- mkKailua secret [block|check if false; check if false;|]
      res <- authorizeKailua kailua [authorizer|deny if true;|]
      res @?= Left(ResultError $ DenyRuleMatched [ifFalse', ifFalse'] ifTrue)
  , testCase "Checks and no policies matched" $ do
      secret <- newSecret
      kailua <- mkKailua secret [block|check if false; check if false;|]
      res <- authorizeKailua kailua [authorizer|allow if false;|]
      res @?= Left (ResultError $ NoPoliciesMatched [ifFalse', ifFalse'])
  ]

unboundVarRule :: TestTree
unboundVarRule = testCase "Rule with unbound variable" $ do
  secret <- newSecret
  b1 <- mkKailua secret [block|check if operation("read");|]
  let brokenRuleBlock = Block {
        bRules = [Rule{
          rhead = Predicate{
            name = "operation",
            terms = [Variable"unbound", LString "read"]
          },
          body = [Predicate{
            name = "operation",
            terms = Variable <$> ["any1", "any2"]
          }],
          expressions = mempty,
          scope = mempty
        }],
        bFacts = mempty,
        bChecks = mempty,
        bScope = mempty,
        bContext = mempty
  }
  b2 <- addBlock brokenRuleBlock b1
  res <- authorizeKailua b2 [authorizer|operation("write");allow if true;|]
  res @?= Left InvalidRule

symbolRestrictions :: TestTree
symbolRestrictions = testGroup "Restricted symbols in blocks"
  [ testCase "In facts" $ do
      secret <- newSecret
      b1 <- mkKailua secret [block|check if operation("read");|]
      b2 <- addBlock [block|operation("read");|] b1
      res <- authorizeKailua b2 [authorizer|allow if true;|]
      res @?= Left (Executor.ResultError $ Executor.FailedChecks $ pure [check|check if operation("read")|])
  , testCase "In rules" $ do
      secret <- newSecret
      b1 <- mkKailua secret [block|check if operation("read");|]
      b2 <- addBlock [block|operation($ambient, "read") <- operation($ambient, $any);|] b1
      res <- authorizeKailua b2 [authorizer|operation("write");allow if true;|]
      res @?= Left (Executor.ResultError $ Executor.FailedChecks $ pure [check|check if operation("read")|])
  ]
