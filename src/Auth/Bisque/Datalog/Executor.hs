{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TupleSections              #-}
{-|
  Module     : Auth.Bisque.Datalog.Executor
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
 -}
module Auth.Bisque.Datalog.Executor ( Bindings
                                    , ExecutionError (..)
                                    , FactGroup (..)
                                    , Limits (..)
                                    , MatchedQuery (..)
                                    , Name
                                    , ResultError (..)
                                    , Scoped
                                    , checkCheck
                                    , checkPolicy
                                    , countFacts
                                    , defaultLimits
                                    , evaluateExpression
                                    , extractVariables
                                    , fromScopedFacts
                                    , getBindingsForRuleBody
                                    , getCombinations
                                    , getFactsForRule
                                    , keepAuthorized'
                                    , toScopedFacts
                                    ) where

import Auth.Bisque.Datalog.AST
import Auth.Bisque.Utils              (maybeToRight)
import Control.Monad                  (join, mfilter, zipWithM)
import Data.Bitraversable             (bitraverse)
import qualified Data.ByteString      as ByteString
import Data.Foldable                  (fold)
import Data.Functor.Compose           (Compose (..))
import Data.List.NonEmpty             (NonEmpty)
import qualified Data.List.NonEmpty   as NE
import Data.Map.Strict                (Map, (!?))
import qualified Data.Map.Strict      as Map
import Data.Maybe                     (fromMaybe, isJust, mapMaybe)
import Data.Set                       (Set)
import qualified Data.Set             as Set
import Data.Text                      (Text, isInfixOf, unpack)
import qualified Data.Text            as Text
import Data.Void                      (absurd)
import Numeric.Natural                (Natural)
import qualified Text.Regex.TDFA      as Regex
import qualified Text.Regex.TDFA.Text as Regex
import Validation                     (Validation (..), failure)

type Name = Text
type Bindings  = Map Name Value
type Scoped a = (Set Natural, a)

newtype FactGroup = FactGroup { getFactGroup :: Map (Set Natural) (Set Fact) } deriving newtype (Eq)

instance Show FactGroup
  where
    show (FactGroup groups) =
      let showGroup (origin, facts) = unlines
            [ "For origin: " <> show (Set.toList origin)
            , "Facts: \n" <> unlines (unpack . renderFact <$> Set.toList facts)
            ]
      in unlines $ showGroup <$> Map.toList groups

instance Semigroup FactGroup
  where
    FactGroup f1 <> FactGroup f2 = FactGroup $ Map.unionWith (<>) f1 f2

instance Monoid FactGroup
  where
    mempty = FactGroup mempty


data MatchedQuery
  = MatchedQuery
  { matchedQuery :: Query
  , bindings     :: Set Bindings
  }
  deriving (Eq, Show)

data ResultError
  = NoPoliciesMatched [Check]
  | FailedChecks      (NonEmpty Check)
  | DenyRuleMatched   [Check] MatchedQuery
  deriving (Eq, Show)

data ExecutionError
  = Timeout
  | TooManyFacts
  | TooManyIterations
  | InvalidRule
  | ResultError ResultError
  deriving (Eq, Show)

data Limits
  = Limits
  { maxFacts      :: Int
  , maxIterations :: Int
  , maxTime       :: Int
  , allowRegexes  :: Bool
  }
  deriving (Eq, Show)

defaultLimits :: Limits
defaultLimits = Limits
  { maxFacts = 1000
  , maxIterations = 100
  , maxTime = 1000
  , allowRegexes = True
  }

keepAuthorized :: FactGroup -> Set Natural -> FactGroup
keepAuthorized (FactGroup facts) authorizedOrigins =
  let isAuthorized k _ = k `Set.isSubsetOf` authorizedOrigins
  in FactGroup $ Map.filterWithKey isAuthorized facts

keepAuthorized' :: FactGroup -> Maybe RuleScope -> Natural -> FactGroup
keepAuthorized' factGroup mScope currentBlockId =
  let scope = fromMaybe OnlyAuthority mScope
  in case scope of
       OnlyAuthority  -> keepAuthorized factGroup (Set.fromList [0, currentBlockId])
       Previous       -> keepAuthorized factGroup (Set.fromList [0..currentBlockId])
       UnsafeAny      -> factGroup
       OnlyBlocks ids -> keepAuthorized factGroup (Set.insert currentBlockId ids)

toScopedFacts :: FactGroup -> Set (Scoped Fact)
toScopedFacts (FactGroup factGroups) =
  let distributeScope scope facts = Set.map (scope,) facts
  in foldMap (uncurry distributeScope) $ Map.toList factGroups

fromScopedFacts :: Set (Scoped Fact) -> FactGroup
fromScopedFacts = FactGroup . Map.fromListWith (<>) . Set.toList . Set.map (fmap Set.singleton)

countFacts :: FactGroup -> Int
countFacts (FactGroup facts) = sum $ Set.size <$> Map.elems facts

isSame :: Term -> Value -> Bool
isSame (LInteger t) (LInteger t') = t == t'
isSame (LString t)  (LString t')  = t == t'
isSame (LDate t)    (LDate t')    = t == t'
isSame (LBytes t)   (LBytes t')   = t == t'
isSame (LBool t)    (LBool t')    = t == t'
isSame (TermSet t)  (TermSet t')  = t == t'
isSame _ _                        = False

mergeBindings :: [Bindings] -> Bindings
mergeBindings =
  let combinations :: [Bindings] -> Map Name (NonEmpty Value)
      combinations = Map.unionsWith (<>) . fmap (fmap pure)
      sameValues = fmap NE.head . mfilter ((== 1) . length) . Just . NE.nub
      keepConsistent = Map.mapMaybe sameValues
  in keepConsistent . combinations

extractVariables :: [Predicate] -> Set Name
extractVariables predicates =
  let keepVariable = \case
        Variable name -> Just name
        _             -> Nothing
      extractVariables' Predicate{terms} = mapMaybe keepVariable terms
  in Set.fromList $ extractVariables' =<< predicates

getCombinations :: [[Scoped Bindings]] -> [Scoped [Bindings]]
getCombinations = getCompose . traverse Compose

reduceCandidateBindings :: Set Name -> [Set (Scoped Bindings)] -> Set (Scoped Bindings)
reduceCandidateBindings allVariables matches =
  let allCombinations :: [(Set Natural, [Bindings])]
      allCombinations = getCombinations $ Set.toList <$> matches
      isComplete :: Scoped Bindings -> Bool
      isComplete = (== allVariables) . Set.fromList . Map.keys . snd
  in Set.fromList $ filter isComplete $ fmap mergeBindings <$> allCombinations

factMatchesPredicate :: Predicate -> Scoped Fact -> Maybe (Scoped Bindings)
factMatchesPredicate Predicate{name = predicateName, terms = predicateTerms }
                     ( factOrigins
                     , Predicate{name = factName, terms = factTerms }
                     ) =
  let namesMatch = predicateName == factName
      lengthsMatch = length predicateTerms == length factTerms
      allMatches = zipWithM compatibleMatch predicateTerms factTerms
      compatibleMatch :: Term -> Value -> Maybe Bindings
      compatibleMatch (Variable vname) value = Just (Map.singleton vname value)
      compatibleMatch t t' | isSame t t' = Just mempty | otherwise   = Nothing
  in if namesMatch && lengthsMatch
     then (factOrigins,) . mergeBindings <$> allMatches
     else Nothing

getCandidateBindings :: Set (Scoped Fact) -> [Predicate] -> [Set (Scoped Bindings)]
getCandidateBindings facts predicates =
  let mapMaybeS :: (Ord a, Ord b) => (a -> Maybe b) -> Set a -> Set b
      mapMaybeS f = foldMap (foldMap Set.singleton . f)
      keepFacts :: Predicate -> Set (Scoped Bindings)
      keepFacts p = mapMaybeS (factMatchesPredicate p) facts
  in keepFacts <$> predicates

applyVariable :: Bindings -> Term -> Either String Value
applyVariable bindings = \case
  Variable n  -> maybeToRight "Unbound variable" $ bindings !? n
  LInteger t  -> Right $ LInteger t
  LString t   -> Right $ LString t
  LDate t     -> Right $ LDate t
  LBytes t    -> Right $ LBytes t
  LBool t     -> Right $ LBool t
  TermSet t   -> Right $ TermSet t
  Antiquote v -> absurd v

regexMatch :: Text -> Text -> Either String Value
regexMatch text regexT = do
  regex  <- Regex.compile Regex.defaultCompOpt Regex.defaultExecOpt regexT
  result <- Regex.execute regex text
  pure . LBool $ isJust result

evalUnary :: Unary -> Value -> Either String Value
evalUnary Parens t = pure t
evalUnary Negate (LBool b) = pure (LBool $ not b)
evalUnary Negate _ = Left "Only booleans support negation"
evalUnary Length (LString t) = pure . LInteger $ Text.length t
evalUnary Length (LBytes bs) = pure . LInteger $ ByteString.length bs
evalUnary Length (TermSet s) = pure . LInteger $ Set.size s
evalUnary Length _ = Left "Only strings, bytes and sets support `.length()`"

evalBinary :: Limits -> Binary -> Value -> Value -> Either String Value
evalBinary _ Equal (LInteger i) (LInteger i') = pure $ LBool (i == i')
evalBinary _ Equal (LString t) (LString t')   = pure $ LBool (t == t')
evalBinary _ Equal (LDate t) (LDate t')       = pure $ LBool (t == t')
evalBinary _ Equal (LBytes t) (LBytes t')     = pure $ LBool (t == t')
evalBinary _ Equal (LBool t) (LBool t')       = pure $ LBool (t == t')
evalBinary _ Equal (TermSet t) (TermSet t')   = pure $ LBool (t == t')
evalBinary _ Equal _ _                        = Left "Equality mismatch"
evalBinary _ LessThan (LInteger i) (LInteger i') = pure $ LBool (i < i')
evalBinary _ LessThan (LDate t) (LDate t')       = pure $ LBool (t < t')
evalBinary _ LessThan _ _                        = Left "< mismatch"
evalBinary _ GreaterThan (LInteger i) (LInteger i') = pure $ LBool (i > i')
evalBinary _ GreaterThan (LDate t) (LDate t')       = pure $ LBool (t > t')
evalBinary _ GreaterThan _ _                        = Left "> mismatch"
evalBinary _ LessOrEqual (LInteger i) (LInteger i') = pure $ LBool (i <= i')
evalBinary _ LessOrEqual (LDate t) (LDate t')       = pure $ LBool (t <= t')
evalBinary _ LessOrEqual _ _                        = Left "<= mismatch"
evalBinary _ GreaterOrEqual (LInteger i) (LInteger i') = pure $ LBool (i >= i')
evalBinary _ GreaterOrEqual (LDate t) (LDate t')       = pure $ LBool (t >= t')
evalBinary _ GreaterOrEqual _ _                        = Left ">= mismatch"
evalBinary _ Prefix (LString t) (LString t') = pure $ LBool (t' `Text.isPrefixOf` t)
evalBinary _ Prefix _ _                      = Left "Only strings support `.starts_with()`"
evalBinary _ Suffix (LString t) (LString t') = pure $ LBool (t' `Text.isSuffixOf` t)
evalBinary _ Suffix _ _                      = Left "Only strings support `.ends_with()`"
evalBinary Limits{allowRegexes} Regex  (LString t) (LString r) | allowRegexes = regexMatch t r
                                                               | otherwise    = Left "Regex evaluation is disabled"
evalBinary _ Regex _ _                       = Left "Only strings support `.matches()`"
evalBinary _ Add (LInteger i) (LInteger i') = pure $ LInteger (i + i')
evalBinary _ Add (LString t) (LString t') = pure $ LString (t <> t')
evalBinary _ Add _ _ = Left "Only integers and strings support addition"
evalBinary _ Sub (LInteger i) (LInteger i') = pure $ LInteger (i - i')
evalBinary _ Sub _ _ = Left "Only integers support subtraction"
evalBinary _ Mul (LInteger i) (LInteger i') = pure $ LInteger (i * i')
evalBinary _ Mul _ _ = Left "Only integers support multiplication"
evalBinary _ Div (LInteger _) (LInteger 0) = Left "Divide by 0"
evalBinary _ Div (LInteger i) (LInteger i') = pure $ LInteger (i `div` i')
evalBinary _ Div _ _ = Left "Only integers support division"
evalBinary _ And (LBool b) (LBool b') = pure $ LBool (b && b')
evalBinary _ And _ _ = Left "Only booleans support &&"
evalBinary _ Or (LBool b) (LBool b') = pure $ LBool (b || b')
evalBinary _ Or _ _ = Left "Only booleans support ||"
evalBinary _ Contains (TermSet t) (TermSet t') = pure $ LBool (Set.isSubsetOf t' t)
evalBinary _ Contains (TermSet t) t' = case toSetTerm t' of
    Just t'' -> pure $ LBool (Set.member t'' t)
    Nothing  -> Left "Sets cannot contain nested sets nor variables"
evalBinary _ Contains (LString t) (LString t') = pure $ LBool (t' `isInfixOf` t)
evalBinary _ Contains _ _ = Left "Only sets and strings support `.contains()`"
evalBinary _ Intersection (TermSet t) (TermSet t') = pure $ TermSet (Set.intersection t t')
evalBinary _ Intersection _ _ = Left "Only sets support `.intersection()`"
evalBinary _ Union (TermSet t) (TermSet t') = pure $ TermSet (Set.union t t')
evalBinary _ Union _ _ = Left "Only sets support `.union()`"

evaluateExpression :: Limits -> Bindings -> Expression -> Either String Value
evaluateExpression l b = \case
    EValue term -> applyVariable b term
    EUnary op e' -> evalUnary op =<< evaluateExpression l b e'
    EBinary op e' e'' -> uncurry (evalBinary l op) =<< join bitraverse (evaluateExpression l b) (e', e'')

satisfies :: Limits -> Scoped Bindings -> Expression -> Bool
satisfies l b e = evaluateExpression l (snd b) e == Right (LBool True)

getBindingsForRuleBody :: Limits -> Set (Scoped Fact) -> [Predicate] -> [Expression] -> Set (Scoped Bindings)
getBindingsForRuleBody l facts body expressions =
  let candidateBindings = getCandidateBindings facts body
      allVariables = extractVariables body
      legalBindingsForFacts = reduceCandidateBindings allVariables candidateBindings
  in Set.filter (\b -> all (satisfies l b) expressions) legalBindingsForFacts

isQueryItemSatisfied :: Limits -> Natural -> FactGroup -> QueryItem' 'RegularString -> Maybe (Set Bindings)
isQueryItemSatisfied l blockId allFacts QueryItem{qBody, qExpressions, qScope} =
  let removeScope = Set.map snd
      facts = toScopedFacts $ keepAuthorized' allFacts qScope blockId
      bindings = removeScope $ getBindingsForRuleBody l facts qBody qExpressions
  in if Set.size bindings > 0
     then Just bindings
     else Nothing

checkCheck :: Limits -> Natural -> FactGroup -> Check -> Validation (NonEmpty Check) ()
checkCheck l checkBlockId facts items =
  if any (isJust . isQueryItemSatisfied l checkBlockId facts) items
  then Success ()
  else failure items

checkPolicy :: Limits -> FactGroup -> Policy -> Maybe (Either MatchedQuery MatchedQuery)
checkPolicy l facts (pType, query) =
  let bindings = fold $ mapMaybe (isQueryItemSatisfied l 0 facts) query
  in if not (null bindings)
     then Just $ case pType of
                   Allow -> Right $ MatchedQuery{matchedQuery = query, bindings}
                   Deny  -> Left $ MatchedQuery{matchedQuery = query, bindings}
     else Nothing

applyBindings :: Predicate -> Scoped Bindings -> Maybe (Scoped Fact)
applyBindings p@Predicate{terms} (origins, bindings) =
  let newTerms = traverse replaceTerm terms
      replaceTerm :: Term -> Maybe Value
      replaceTerm (Variable n)  = Map.lookup n bindings
      replaceTerm (LInteger t)  = Just $ LInteger t
      replaceTerm (LString t)   = Just $ LString t
      replaceTerm (LDate t)     = Just $ LDate t
      replaceTerm (LBytes t)    = Just $ LBytes t
      replaceTerm (LBool t)     = Just $ LBool t
      replaceTerm (TermSet t)   = Just $ TermSet t
      replaceTerm (Antiquote t) = absurd t
  in (\nt -> (origins, p { terms = nt})) <$> newTerms

getFactsForRule :: Limits -> Set (Scoped Fact) -> Rule -> Set (Scoped Fact)
getFactsForRule l facts Rule{rhead, body, expressions} =
  let legalBindings :: Set (Scoped Bindings)
      legalBindings = getBindingsForRuleBody l facts body expressions
      newFacts = mapMaybe (applyBindings rhead) $ Set.toList legalBindings
  in Set.fromList newFacts
