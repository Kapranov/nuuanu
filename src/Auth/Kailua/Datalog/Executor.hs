{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE TupleSections              #-}
{-# LANGUAGE TypeApplications           #-}
{-|
  Module      : Auth.Kailua.Datalog.Executor
  Copyright   : updated © Oleg G.Kapranov, 2025
  License     : MIT
  Maintainer  : lugatex@yahoo.com
  The Datalog engine, tasked with deriving new facts from existing facts and rules, as well as matching available facts against checks and policies
-}
module Auth.Kailua.Datalog.Executor ( Bindings
                                    , ExecutionError (..)
                                    , FactGroup (..)
                                    , Limits (..)
                                    , MatchedQuery (..)
                                    , Names
                                    , ResultError (..)
                                    , Scoped
                                    , checkCheck
                                    , checkPolicy
                                    , countFacts
                                    , defaultLimits
                                    , evaluateExpression
                                    , fromScopedFacts
                                    , getBindingsForRuleBody
                                    , getCombinations
                                    , getFactsForRule
                                    , keepAuthorized'
                                    , toScopedFacts
                                    ) where

import           Auth.Kailua.Datalog.AST   ( Binary (..)
                                           , Check
                                           , Check' (..)
                                           , CheckKind (..)
                                           , DatalogContext (..)
                                           , EvalCheck
                                           , EvalPolicy
                                           , EvalRule
                                           , EvalRuleScope
                                           , EvaluationContext (..)
                                           , Expression
                                           , Expression' (..)
                                           , Fact
                                           , PolicyType (..)
                                           , Predicate
                                           , Predicate' (..)
                                           , QueryItem' (..)
                                           , Rule' (..)
                                           , RuleScope' (..)
                                           , Term
                                           , Term' (..)
                                           , ToEvaluation (..)
                                           , Unary (..)
                                           , Value
                                           , extractVariables
                                           , valueToSetTerm
                                           )
import           Auth.Kailua.Datalog.Types ( Bindings
                                           , ExecutionError (..)
                                           , FactGroup (..)
                                           , Limits (..)
                                           , MatchedQuery (..)
                                           , Names
                                           , ResultError (..)
                                           , Scoped
                                           )
import           Auth.Kailua.Utils         ( allM
                                           , anyM
                                           , maybeToRight
                                           , setFilterM
                                           )
import           Control.Monad             ( join
                                           , mfilter
                                           , zipWithM
                                           )
import           Data.Bitraversable        (bitraverse)
import           Data.Bits                 (xor, (.&.), (.|.))
import qualified Data.ByteString           as ByteString
import           Data.Foldable             (fold)
import           Data.Functor.Compose      (Compose (..))
import           Data.Int                  (Int64)
import           Data.List.NonEmpty        (NonEmpty)
import qualified Data.List.NonEmpty        as NE
import           Data.Map.Strict           (Map, (!?))
import qualified Data.Map.Strict           as Map
import           Data.Maybe                ( isJust
                                           , mapMaybe
                                           )
import           Data.Set                  (Set)
import qualified Data.Set                  as Set
import           Data.Text                 ( Text
                                           , isInfixOf
                                           )
import qualified Data.Text                 as Text
import qualified Data.Text.Encoding        as Text
import           Data.Void                 (absurd)
import           Numeric.Natural           (Natural)
import qualified Text.Regex.TDFA           as Regex
import qualified Text.Regex.TDFA.Text      as Regex
import           Validation                ( Validation (..)
                                           , failure
                                           )

keepAuthorized :: FactGroup -> Set Natural -> FactGroup
keepAuthorized (FactGroup facts) authorizedOrigins =
  let isAuthorized k _ = k `Set.isSubsetOf` authorizedOrigins
  in FactGroup $ Map.filterWithKey isAuthorized facts

keepAuthorized' :: Bool -> Natural -> FactGroup -> Set EvalRuleScope -> Natural -> FactGroup
keepAuthorized' allowPreviousInAuthorizer blockCount factGroup trustedBlocks currentBlockId =
  let scope = if null trustedBlocks then Set.singleton OnlyAuthority else trustedBlocks
      toBlockIds = \case
        OnlyAuthority    -> Set.singleton 0
        Previous         -> if allowPreviousInAuthorizer || currentBlockId < blockCount
                            then Set.fromList [0..currentBlockId]
                            else mempty
        BlockId (idx, _) -> idx
      allBlockIds = foldMap toBlockIds scope
  in keepAuthorized factGroup $ Set.insert currentBlockId $ Set.insert blockCount allBlockIds

toScopedFacts :: FactGroup -> Set (Scoped Fact)
toScopedFacts (FactGroup factGroups) =
  let distributeScope scope = Set.map (scope,)
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
  let combinations :: [Bindings] -> Map Names (NonEmpty Value)
      combinations = Map.unionsWith (<>) . fmap (fmap pure)
      sameValues = fmap NE.head . mfilter ((== 1) . length) . Just . NE.nub
      keepConsistent = Map.mapMaybe sameValues
  in keepConsistent . combinations

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
      compatibleMatch t t' | isSame t t' = Just mempty
                | otherwise   = Nothing
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

getCombinations :: [[Scoped Bindings]] -> [Scoped [Bindings]]
getCombinations = getCompose . traverse Compose

reduceCandidateBindings :: Set Names -> [Set (Scoped Bindings)] -> Set (Scoped Bindings)
reduceCandidateBindings allVariables matches =
  let allCombinations :: [(Set Natural, [Bindings])]
      allCombinations = getCombinations $ Set.toList <$> matches
      isComplete :: Scoped Bindings -> Bool
      isComplete = (== allVariables) . Set.fromList . Map.keys . snd
  in Set.fromList $ filter isComplete $ fmap mergeBindings <$> allCombinations

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

evalUnary :: Unary -> Value -> Either String Value
evalUnary Parens t = pure t
evalUnary Negate (LBool b) = pure (LBool $ not b)
evalUnary Negate _ = Left "Only booleans support negation"
evalUnary Length (LString t) = pure . LInteger . fromIntegral $ ByteString.length $ Text.encodeUtf8 t
evalUnary Length (LBytes bs) = pure . LInteger . fromIntegral $ ByteString.length bs
evalUnary Length (TermSet s) = pure . LInteger . fromIntegral $ Set.size s
evalUnary Length _ = Left "Only strings, bytes and sets support `.length()`"

regexMatch :: Text -> Text -> Either String Value
regexMatch text regexT = do
  regex  <- Regex.compile Regex.defaultCompOpt Regex.defaultExecOpt regexT
  result <- Regex.execute regex text
  pure . LBool $ isJust result

checkedOp :: (Integer -> Integer -> Integer) -> Int64 -> Int64 -> Either String Int64
checkedOp f a b =
  let result = f (fromIntegral a) (fromIntegral b)
  in if result < fromIntegral (minBound @Int64)
     then Left "integer underflow"
     else if result > fromIntegral (maxBound @Int64)
     then Left "integer overflow"
     else Right (fromIntegral result)

evalBinary :: Limits -> Binary -> Value -> Value -> Either String Value
evalBinary _ Equal (LInteger i) (LInteger i') = pure $ LBool (i == i')
evalBinary _ Equal (LString t) (LString t')   = pure $ LBool (t == t')
evalBinary _ Equal (LDate t) (LDate t')       = pure $ LBool (t == t')
evalBinary _ Equal (LBytes t) (LBytes t')     = pure $ LBool (t == t')
evalBinary _ Equal (LBool t) (LBool t')       = pure $ LBool (t == t')
evalBinary _ Equal (TermSet t) (TermSet t')   = pure $ LBool (t == t')
evalBinary _ Equal _ _                        = Left "Equality mismatch"
evalBinary _ NotEqual (LInteger i) (LInteger i') = pure $ LBool (i /= i')
evalBinary _ NotEqual (LString t) (LString t')   = pure $ LBool (t /= t')
evalBinary _ NotEqual (LDate t) (LDate t')       = pure $ LBool (t /= t')
evalBinary _ NotEqual (LBytes t) (LBytes t')     = pure $ LBool (t /= t')
evalBinary _ NotEqual (LBool t) (LBool t')       = pure $ LBool (t /= t')
evalBinary _ NotEqual (TermSet t) (TermSet t')   = pure $ LBool (t /= t')
evalBinary _ NotEqual _ _                        = Left "Inequity mismatch"
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
evalBinary _ Add (LInteger i) (LInteger i') = LInteger <$> checkedOp (+) i i'
evalBinary _ Add (LString t) (LString t') = pure $ LString (t <> t')
evalBinary _ Add _ _ = Left "Only integers and strings support addition"
evalBinary _ Sub (LInteger i) (LInteger i') = LInteger <$> checkedOp (-) i i'
evalBinary _ Sub _ _ = Left "Only integers support subtraction"
evalBinary _ Mul (LInteger i) (LInteger i') = LInteger <$> checkedOp (*) i i'
evalBinary _ Mul _ _ = Left "Only integers support multiplication"
evalBinary _ Div (LInteger _) (LInteger 0) = Left "Divide by 0"
evalBinary _ Div (LInteger i) (LInteger i') = LInteger <$> checkedOp div i i'
evalBinary _ Div _ _ = Left "Only integers support division"
-- bitwise operations
evalBinary _ BitwiseAnd (LInteger i) (LInteger i') = pure $ LInteger (i .&. i')
evalBinary _ BitwiseAnd _ _ = Left "Only integers support bitwise and"
evalBinary _ BitwiseOr  (LInteger i) (LInteger i') = pure $ LInteger (i .|. i')
evalBinary _ BitwiseOr _ _ = Left "Only integers support bitwise or"
evalBinary _ BitwiseXor (LInteger i) (LInteger i') = pure $ LInteger (i `xor` i')
evalBinary _ BitwiseXor _ _ = Left "Only integers support bitwise xor"
-- boolean operations
evalBinary _ And (LBool b) (LBool b') = pure $ LBool (b && b')
evalBinary _ And _ _ = Left "Only booleans support &&"
evalBinary _ Or (LBool b) (LBool b') = pure $ LBool (b || b')
evalBinary _ Or _ _ = Left "Only booleans support ||"
-- set operations
evalBinary _ Contains (TermSet t) (TermSet t') = pure $ LBool (Set.isSubsetOf t' t)
evalBinary _ Contains (TermSet t) t' = case valueToSetTerm t' of
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

satisfies :: Limits -> Scoped Bindings -> Expression -> Either String Bool
satisfies l b e = (== LBool True) <$> evaluateExpression l (snd b) e

getBindingsForRuleBody :: Limits -> Set (Scoped Fact) -> [Predicate] -> [Expression] -> Either String (Set (Scoped Bindings))
getBindingsForRuleBody l facts body expressions =
  let candidateBindings = getCandidateBindings facts body
      allVariables = extractVariables body
      legalBindingsForFacts = reduceCandidateBindings allVariables candidateBindings
  in setFilterM (\b -> allM (satisfies l b) expressions) legalBindingsForFacts

isQueryItemSatisfied :: Limits -> Natural -> Natural -> FactGroup -> QueryItem' 'Eval 'Representation -> Either String (Maybe (Set Bindings))
isQueryItemSatisfied l blockCount blockId allFacts QueryItem{qBody, qExpressions, qScope} = do
  let removeScope = Set.map snd
      facts = toScopedFacts $ keepAuthorized' False blockCount allFacts qScope blockId
  bindings <- removeScope <$> getBindingsForRuleBody l facts qBody qExpressions
  pure $ if Set.size bindings > 0
         then Just bindings
         else Nothing

isQueryItemSatisfiedForAllMatches :: Limits -> Natural -> Natural -> FactGroup -> QueryItem' 'Eval 'Representation -> Either String (Maybe (Set Bindings))
isQueryItemSatisfiedForAllMatches l blockCount blockId allFacts QueryItem{qBody, qExpressions, qScope} = do
  let removeScope = Set.map snd
      facts = toScopedFacts $ keepAuthorized' False blockCount allFacts qScope blockId
      allVariables = extractVariables qBody
      candidateBindings = getCandidateBindings facts qBody
      legalBindingsForFacts = reduceCandidateBindings allVariables candidateBindings
  constraintFulfillingBindings <- setFilterM (\b -> allM (satisfies l b) qExpressions) legalBindingsForFacts
  pure $ if Set.size constraintFulfillingBindings > 0 -- there is at least one match that fulfills the constraints
         && constraintFulfillingBindings == legalBindingsForFacts -- all matches fulfill the constraints
         then Just $ removeScope constraintFulfillingBindings
         else Nothing

checkCheck :: Limits -> Natural -> Natural -> FactGroup -> EvalCheck -> Either String (Validation (NonEmpty Check) ())
checkCheck l blockCount checkBlockId facts c@Check{cQueries,cKind} = do
  let isQueryItemOk = case cKind of
        One -> isQueryItemSatisfied l blockCount checkBlockId facts
        All -> isQueryItemSatisfiedForAllMatches l blockCount checkBlockId facts
  hasOkQueryItem <- anyM (fmap isJust . isQueryItemOk) cQueries
  pure $ if hasOkQueryItem
         then Success ()
         else failure (toRepresentation c)

checkPolicy :: Limits -> Natural -> FactGroup -> EvalPolicy -> Either String (Maybe (Either MatchedQuery MatchedQuery))
checkPolicy l blockCount facts (pType, query) = do
  bindings <- fold . fold <$> traverse (isQueryItemSatisfied l blockCount blockCount facts) query
  pure $ if not (null bindings)
         then Just $ case pType of
           Allow -> Right $ MatchedQuery{matchedQuery = toRepresentation <$> query, bindings}
           Deny  -> Left $ MatchedQuery{matchedQuery = toRepresentation <$> query, bindings}
         else Nothing

defaultLimits :: Limits
defaultLimits = Limits
  { maxFacts = 1000
  , maxIterations = 100
  , maxTime = 1000
  , allowRegexes = True
  }

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

getFactsForRule :: Limits -> Set (Scoped Fact) -> EvalRule -> Either String (Set (Scoped Fact))
getFactsForRule l facts Rule{rhead, body, expressions} = do
  legalBindings <- getBindingsForRuleBody l facts body expressions
  pure $ Set.fromList $ mapMaybe (applyBindings rhead) $ Set.toList legalBindings
