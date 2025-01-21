{-# LANGUAGE OverloadedLists   #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Spec.Auth.Kailua.Quasiquoter (specs) where

import Auth.Kailua.Datalog.AST    ( Fact
                                  , Predicate' (..)
                                  , Rule
                                  , Rule' (..)
                                  , Term' (..)
                                  )
import Auth.Kailua.Datalog.Parser (fact, rule)
import Data.Text                  (Text)
import Test.Tasty
import Test.Tasty.HUnit

specs :: TestTree
specs = testGroup "Datalog quasiquoter"
  [ basicFact
  , basicRule
  , antiquotedFact
  , antiquotedRule
  ]

basicFact :: TestTree
basicFact = testCase "Basic fact" $
  let actual :: Fact
      actual = [fact|right("file1", "read")|]
   in actual @?=
    Predicate "right" [ LString "file1"
                      , LString "read"
                      ]

basicRule :: TestTree
basicRule = testCase "Basic rule" $
  let actual :: Rule
      actual = [rule|right($0, "read") <- resource( $0), operation("read")|]
   in actual @?=
    Rule (Predicate "right" [Variable "0", LString "read"])
         [ Predicate "resource" [Variable "0"]
         , Predicate "operation" [LString "read"]
         ] [] []

antiquotedFact :: TestTree
antiquotedFact = testCase "Sliced fact" $
  let toto2' :: Text
      toto2' = "test"
      actual :: Fact
      actual = [fact|right({toto2'}, "read")|]
   in actual @?=
    Predicate "right" [ LString "test"
                      , LString "read"
                      ]

antiquotedRule :: TestTree
antiquotedRule = testCase "Sliced rule" $
  let toto :: Text
      toto = "test"
      actual :: Rule
      actual = [rule|right($0, "read") <- resource( $0), operation("read", {toto})|]
   in actual @?=
    Rule (Predicate "right" [Variable "0", LString "read"])
         [ Predicate "resource" [Variable "0"]
         , Predicate "operation" [LString "read", LString "test"]
         ] [] []
