{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
{-# LANGUAGE RecordWildCards   #-}
module Spec.Auth.Bisque.Verification (specs) where

import Auth.Bisque ( AuthorizationSuccess (..)
                   , ExecutionError (..)
                   , addBlock
                   , authorizeBisque
                   , authorizer
                   , block
                   , mkBisque
                   , newSecret
                   , query
                   )
import Auth.Bisque.Datalog.AST                (Query)
import Auth.Bisque.Datalog.Executor           ( MatchedQuery (..)
                                              , ResultError (..)
                                              )
import qualified Auth.Bisque.Datalog.Executor as Executor
import Auth.Bisque.Datalog.Parser             (check)
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

ifFalse' :: Query
ifFalse' = matchedQuery ifFalse

singleBlock :: TestTree
singleBlock = testCase "Single block" $ do
  secret <- newSecret
  bisque <- mkBisque secret [block|right("file1", "read");|]
  res <- authorizeBisque bisque [authorizer|check if right("file1", "read");allow if true;|]
  matchedAllowQuery <$> res @?= Right ifTrue

errorAccumulation :: TestTree
errorAccumulation = testGroup "Error accumulation"
  [ testCase "Only checks" $ do
      secret <- newSecret
      bisque <- mkBisque secret[block|check if false; check if false;|]
      res <- authorizeBisque bisque [authorizer|allow if true;|]
      res @?= Left (ResultError $ FailedChecks $ ifFalse' :| [ifFalse'])
  , testCase "Checks and deny policies" $ do
      secret <- newSecret
      bisque <- mkBisque secret [block|check if false; check if false;|]
      res <- authorizeBisque bisque [authorizer|deny if true;|]
      res @?= Left(ResultError $ DenyRuleMatched [ifFalse', ifFalse'] ifTrue)
  , testCase "Checks and no policies matched" $ do
      secret <- newSecret
      bisque <- mkBisque secret [block|check if false; check if false;|]
      res <- authorizeBisque bisque [authorizer|allow if false;|]
      res @?= Left (ResultError $ NoPoliciesMatched [ifFalse', ifFalse'])
  ]

unboundVarRule :: TestTree
unboundVarRule = testCase "Rule with unbound variable" $ do
  secret <- newSecret
  b1 <- mkBisque secret [block|check if operation("read");|]
  b2 <- addBlock [block|operation($unbound, "read") <- operation($any1, $any2);|] b1
  res <- authorizeBisque b2 [authorizer|operation("write");allow if true;|]
  res @?= Left InvalidRule

symbolRestrictions :: TestTree
symbolRestrictions = testGroup "Restricted symbols in blocks"
  [ testCase "In facts" $ do
      secret <- newSecret
      b1 <- mkBisque secret [block|check if operation("read");|]
      b2 <- addBlock [block|operation("read");|] b1
      res <- authorizeBisque b2 [authorizer|allow if true;|]
      res @?= Left (Executor.ResultError $ Executor.FailedChecks $ pure [check|check if operation("read")|])
  , testCase "In rules" $ do
      secret <- newSecret
      b1 <- mkBisque secret [block|check if operation("read");|]
      b2 <- addBlock [block|operation($ambient, "read") <- operation($ambient, $any);|] b1
      res <- authorizeBisque b2 [authorizer|operation("write");allow if true;|]
      res @?= Left (Executor.ResultError $ Executor.FailedChecks $ pure [check|check if operation("read")|])
  ]

specs :: TestTree
specs = testGroup "Datalog checks"
  [ singleBlock
  , errorAccumulation
  , unboundVarRule
  , symbolRestrictions
  ]
