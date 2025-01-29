{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Spec.Auth.Kailua.ScopedExecutor (specs) where

import Auth.Kailua                        ( addBlock
                                          , addSignedBlock
                                          , authorizeKailua
                                          , mkKailua
                                          , newSecret
                                          , queryAuthorizerFacts
                                          , queryRawKailuaFacts
                                          )
import Auth.Kailua.Crypto                 ( generateSecretKey
                                          , toPublic
                                          )
import Auth.Kailua.Datalog.AST            (Term' (..))
import Auth.Kailua.Datalog.Executor       ( ExecutionError (..)
                                          , Limits (..)
                                          , ResultError (..)
                                          , defaultLimits
                                          )
import Auth.Kailua.Datalog.Parser         ( authorizer
                                          , block
                                          , check
                                          , query
                                          )
import Auth.Kailua.Datalog.ScopedExecutor (runAuthorizerNoTimeout)
import Control.Arrow                      ((&&&))
import Data.Either                        (isRight)
import Data.Map.Strict                    as Map
import Data.Set                           as Set
import Test.Tasty
import Test.Tasty.HUnit

specs :: TestTree
specs = testGroup "Block-scoped Datalog Evaluation"
  [ authorizerOnlySeesAuthority
  , authorityOnlySeesItselfAndAuthorizer
  , block1OnlySeesAuthorityAndAuthorizer
  , block2OnlySeesAuthorityAndAuthorizer
  , block1SeesAuthorityAndAuthorizer
  , thirdPartyBlocks
  , iterationCountWorks
  , maxFactsCountWorks
  , allChecksAreCollected
  , revocationIdsAreInjected
  , authorizerFactsAreQueried
  , kailuaFactsAreQueried
  ]

authorizerOnlySeesAuthority :: TestTree
authorizerOnlySeesAuthority = testCase "Authorizer only accesses facts from authority" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         is_allowed(1234, "file1", "write");
       |]
      verif =
       [authorizer|
         allow if is_allowed(1234, "file1", "write");
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left (ResultError (NoPoliciesMatched []))

authorityOnlySeesItselfAndAuthorizer :: TestTree
authorityOnlySeesItselfAndAuthorizer = testCase "Authority rules only see authority and authorizer facts" $ do
  let authority =
       [block|
         user(1234);
         is_allowed($user, $resource) <- right($user, $resource, "read");
       |]
      block1 =
       [block|
         right(1234, "file1", "read");
       |]
      verif =
       [authorizer|
         allow if is_allowed(1234, "file1");
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left (ResultError (NoPoliciesMatched []))

block1OnlySeesAuthorityAndAuthorizer :: TestTree
block1OnlySeesAuthorityAndAuthorizer = testCase "Arbitrary blocks only see previous blocks" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         is_allowed($user, $resource) <- right($user, $resource, "read");
         check if is_allowed(1234, "file1");
       |]
      block2 =
       [block|
         right(1234, "file1", "read");
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing), (block2, "", Nothing)] verif @?= Left (ResultError (FailedChecks $ pure [check|check if is_allowed(1234, "file1") |]))

block2OnlySeesAuthorityAndAuthorizer :: TestTree
block2OnlySeesAuthorityAndAuthorizer = testCase "Arbitrary blocks only see previous blocks" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         right(1234, "file1", "read");
       |]
      block2 =
       [block|
         is_allowed($user, $resource) <- right($user, $resource, "read");
         check if is_allowed(1234, "file1");
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing), (block2, "", Nothing)] verif @?= Left (ResultError (FailedChecks $ pure [check|check if is_allowed(1234, "file1") |]))

block1SeesAuthorityAndAuthorizer :: TestTree
block1SeesAuthorityAndAuthorizer = testCase "Arbitrary blocks see previous blocks" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         is_allowed($user, $resource) <- user($user), right($user, $resource, "read");
         right(1234, "file1", "read");
         check if is_allowed(1234, "file1");
       |]
      verif =
       [authorizer| allow if false;
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left (ResultError $ NoPoliciesMatched [])

thirdPartyBlocks :: TestTree
thirdPartyBlocks = testCase "Third party blocks are correctly scoped" $ do
    (_sk1, pkOne) <- (id &&& toPublic) <$> generateSecretKey
    let authority =
          [block|
            user(1234);
            check if from3rd(1, true) trusting {pkOne};
            check if from3rd(2, true) trusting {pkOne};
          |]
        block1 =
          [block|
          from3rd(1, true);
          |]
        block2 =
          [block|
          from3rd(2, true);
          |]
        verif =
          [authorizer|
            deny if from3rd(1, true);
            allow if from3rd(1, true), from3rd(2, true) trusting {pkOne};
          |]
    let result = runAuthorizerNoTimeout defaultLimits
                   (authority, "", Nothing)
                   [ (block1, "", Just pkOne)
                   , (block2, "", Just pkOne)
                   ]
                   verif
    isRight result @?= True

iterationCountWorks :: TestTree
iterationCountWorks = testCase "ScopedExecutions stops when hitting the iterations threshold" $ do
  let lts = defaultLimits { maxIterations = 8 }
      authority =
       [block|
         a("yolo");
         b($a) <- a($a);
         c($b) <- b($b);
         d($c) <- c($c);
         e($d) <- d($d);
         f($e) <- e($e);
         g($f) <- f($f);
       |]
      block1 =
       [block|
         h($g) <- g($g);
         i($h) <- h($h);
         j($i) <- i($i);
         k($j) <- j($j);
         l($k) <- k($k);
         m($l) <- l($l);
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout lts (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left TooManyIterations

maxFactsCountWorks :: TestTree
maxFactsCountWorks = testCase "ScopedExecutions stops when hitting the facts threshold" $ do
  let lts = defaultLimits { maxFacts = 8 }
      authority =
       [block|
         a("yolo");
         b($a) <- a($a);
         c($b) <- b($b);
         d($c) <- c($c);
         e($d) <- d($d);
         f($e) <- e($e);
         g($f) <- f($f);
       |]
      block1 =
       [block|
         h($g) <- g($g);
         i($h) <- h($h);
         j($i) <- i($i);
         k($j) <- j($j);
         l($k) <- k($k);
         m($l) <- l($l);
       |]
      verif =
       [authorizer|
         allow if true;
       |]
  runAuthorizerNoTimeout lts (authority, "", Nothing) [(block1, "", Nothing)] verif @?= Left TooManyFacts

allChecksAreCollected :: TestTree
allChecksAreCollected = testCase "ScopedExecutions collects all facts results even after a failure" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|
         check if false;
       |]
      block2 =
       [block|
         check if false;
       |]
      verif =
       [authorizer|
         allow if user(4567);
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "", Nothing) [(block1, "", Nothing), (block2, "", Nothing)] verif @?= Left (ResultError $ NoPoliciesMatched [[check|check if false|], [check|check if false|]])

revocationIdsAreInjected :: TestTree
revocationIdsAreInjected = testCase "ScopedExecutions injects revocation ids" $ do
  let authority =
       [block|
         user(1234);
       |]
      block1 =
       [block|yolo("block1");|]
      block2 =
       [block|yolo("block2");|]
      verif =
       [authorizer|
         check if revocation_id(0, hex:61),
                  revocation_id(1, hex:62),
                  revocation_id(2, hex:63);
       |]
  runAuthorizerNoTimeout defaultLimits (authority, "a", Nothing) [(block1, "b", Nothing), (block2, "c", Nothing)] verif @?= Left (ResultError $ NoPoliciesMatched [])

authorizerFactsAreQueried :: TestTree
authorizerFactsAreQueried = testGroup "AuthorizedKailua can be queried"
  [ testCase "Attenuation blocks are ignored" $ do
      (_pk,sk) <- (toPublic &&& id) <$> newSecret
      b <- mkKailua sk [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      result <- authorizeKailua b1 [authorizer|allow if true;|]
      let getUser s = queryAuthorizerFacts s [query|user($user)|]
          expected = Set.singleton $ Map.fromList
            [ ("user", LInteger 1234)
            ]
      getUser <$> result @?= Right (Right expected)
  , testCase "Attenuation blocks can be accessed if asked nicely" $ do
      (_pk,sk) <- (toPublic &&& id) <$> newSecret
      b <- mkKailua sk [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      result <- authorizeKailua b1 [authorizer|allow if true;|]
      let getUser s = queryAuthorizerFacts s [query|user($user) trusting previous|]
          expected = Set.fromList
            [ Map.fromList [("user", LInteger 1234)]
            , Map.fromList [("user", LString "tampered value")]
            ]
      getUser <$> result @?= Right (Right expected)
  , testCase "Signed blocks can be accessed if asked nicely" $ do
      (_pk,sk) <- (toPublic &&& id) <$> newSecret
      (p1,s1) <- (toPublic &&& id) <$> newSecret
      b <- mkKailua sk [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      b2 <- addSignedBlock s1 [block|user("from signed");|] b1
      result <- authorizeKailua b2 [authorizer|allow if true;|]
      let getUser s = queryAuthorizerFacts s [query|user($user) trusting authority, {p1}|]
          expected = Set.fromList
            [ Map.fromList [("user", LInteger 1234)]
            , Map.fromList [("user", LString "from signed")]
            ]
      getUser <$> result @?= Right (Right expected)
  ]

kailuaFactsAreQueried :: TestTree
kailuaFactsAreQueried = testGroup "Kailua can be queried"
  [ testCase "Attenuation blocks are ignored" $ do
      (_p,s) <- (toPublic &&& id) <$> newSecret
      b <- mkKailua s [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      let user = queryRawKailuaFacts b1 [query|user($user)|]
          expected = Set.singleton $ Map.fromList
            [ ("user", LInteger 1234)
            ]
      user @?= Right expected
  , testCase "Attenuation blocks can be accessed if asked nicely" $ do
      (_p,s) <- (toPublic &&& id) <$> newSecret
      b <- mkKailua s [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      let user = queryRawKailuaFacts b1 [query|user($user) trusting previous|]
          expected = Set.fromList
            [ Map.fromList [("user", LInteger 1234)]
            , Map.fromList [("user", LString "tampered value")]
            ]
      user @?= Right expected
  , testCase "Signed blocks can be accessed if asked nicely" $ do
      (_p,s) <- (toPublic &&& id) <$> newSecret
      (p1,s1) <- (toPublic &&& id) <$> newSecret
      b <- mkKailua s [block|user(1234);|]
      b1 <- addBlock [block|user("tampered value");|] b
      b2 <- addSignedBlock s1 [block|user("from signed");|] b1
      let user = queryRawKailuaFacts b2 [query|user($user) trusting authority, {p1}|]
          expected = Set.fromList
            [ Map.fromList [("user", LInteger 1234)]
            , Map.fromList [("user", LString "from signed")]
            ]
      user @?= Right expected
  ]
