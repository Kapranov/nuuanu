{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE DuplicateRecordFields      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE TupleSections              #-}
{-|
  Module     : Auth.Biscuit.Datalog.ScopedExecutor
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
-}
module Auth.Bisque.Datalog.ScopedExecutor ( AuthorizationSuccess (..)
                                          , BlockWithRevocationId
                                          , FactGroup (..)
                                          , PureExecError (..)
                                          , getBindings
                                          , getSingleVariableValue
                                          , getVariableValues
                                          , queryAuthorizerFacts
                                          , runAuthorizer
                                          , runAuthorizerNoTimeout
                                          , runAuthorizerWithLimits
                                          , runFactGeneration
                                          ) where

import Auth.Bisque.Datalog.AST
import Auth.Bisque.Datalog.Executor ( Bindings
                                    , ExecutionError (..)
                                    , FactGroup (..)
                                    , Limits (..)
                                    , MatchedQuery (..)
                                    , ResultError (..)
                                    , Scoped
                                    , checkCheck
                                    , checkPolicy
                                    , countFacts
                                    , defaultLimits
                                    , extractVariables
                                    , fromScopedFacts
                                    , getBindingsForRuleBody
                                    , getFactsForRule
                                    , keepAuthorized'
                                    , toScopedFacts
                                    )
import Auth.Bisque.Datalog.Parser   (fact)
import Auth.Bisque.Timer            (timer)
import Control.Applicative          ((<|>))
import Control.Monad                (unless, when)
import Control.Monad.State          (StateT (..), evalStateT, get, gets, lift, put)
import Data.Bifunctor               (first)
import Data.ByteString              (ByteString)
import Data.Foldable                (fold, traverse_)
import Data.List.NonEmpty           (NonEmpty)
import qualified Data.List.NonEmpty           as NE
import Data.Map                     (Map)
import qualified Data.Map                     as Map
import Data.Map.Strict              ((!?))
import Data.Maybe                   (mapMaybe)
import Data.Set                     (Set)
import qualified Data.Set                     as Set
import Data.Text                    (Text)
import Numeric.Natural              (Natural)
import Validation                   (Validation (..))

type BlockWithRevocationId = (Block, ByteString)

data PureExecError
  = Facts | Iterations | BadRule
  deriving (Eq, Show)

data AuthorizationSuccess
  = AuthorizationSuccess
  { matchedAllowQuery :: MatchedQuery
  , allFacts          :: FactGroup
  , limits            :: Limits
  }
  deriving (Eq, Show)

data ComputeState
  = ComputeState
  { sLimits     :: Limits
  , sRules      :: Map Natural (Set Rule)
  , sIterations :: Int
  , sFacts      :: FactGroup
  }
  deriving (Eq, Show)

getBindings :: AuthorizationSuccess -> Set Bindings
getBindings AuthorizationSuccess{matchedAllowQuery=MatchedQuery{bindings}} = bindings

mkRevocationIdFacts :: BlockWithRevocationId -> [BlockWithRevocationId] -> Set Fact
mkRevocationIdFacts authority blocks =
  let allIds :: [(Int, ByteString)]
      allIds = zip [0..] $ snd <$> authority : blocks
      mkFact (index, rid) = [fact|revocation_id(${index}, ${rid})|]
  in Set.fromList $ mkFact <$> allIds

collectWorld :: Natural -> Block -> (Map Natural (Set Rule), FactGroup)
collectWorld blockId Block{..} =
  let applyScope r@Rule{scope} = r { scope = scope <|> bScope }
  in ( Map.singleton blockId $ Set.map applyScope $ Set.fromList bRules
     , FactGroup $ Map.singleton (Set.singleton blockId) $ Set.fromList bFacts
     )

mkInitState :: Limits -> BlockWithRevocationId -> [BlockWithRevocationId] -> Authorizer -> ComputeState
mkInitState limits authority blocks authorizer =
  let revocationWorld = (mempty, FactGroup $ Map.singleton (Set.singleton 0) $ mkRevocationIdFacts authority blocks)
      firstBlock = fst authority <> vBlock authorizer
      otherBlocks = fst <$> blocks
      allBlocks = firstBlock : otherBlocks
      (sRules, sFacts) = revocationWorld <> fold (zipWith collectWorld [0..] allBlocks)
  in ComputeState
       { sLimits = limits
       , sRules
       , sFacts
       , sIterations = 0
       }

checkRuleHead :: Rule -> Bool
checkRuleHead Rule{rhead, body} =
  let headVars = extractVariables [rhead]
      bodyVars = extractVariables body
  in headVars `Set.isSubsetOf` bodyVars

extend :: Limits -> Map Natural (Set Rule) -> FactGroup -> FactGroup
extend l rules facts =
  let buildFacts :: Natural -> Set Rule -> FactGroup -> Set (Scoped Fact)
      buildFacts ruleBlockId ruleGroup factGroup =
        let extendRule :: Rule -> Set (Scoped Fact)
            extendRule r@Rule{scope} = getFactsForRule l (toScopedFacts $ keepAuthorized' factGroup scope ruleBlockId) r
        in foldMap extendRule ruleGroup
      extendRuleGroup :: Natural -> Set Rule -> FactGroup
      extendRuleGroup ruleBlockId ruleGroup =
        let authorizedFacts = facts
            addRuleOrigin = FactGroup . Map.mapKeysWith (<>) (Set.insert ruleBlockId) . getFactGroup
        in addRuleOrigin . fromScopedFacts $ buildFacts ruleBlockId ruleGroup authorizedFacts
  in foldMap (uncurry extendRuleGroup) $ Map.toList rules

runStep :: StateT ComputeState (Either PureExecError) Int
runStep = do
  state@ComputeState{sLimits,sFacts,sRules,sIterations} <- get
  let Limits{maxFacts, maxIterations} = sLimits
      previousCount = countFacts sFacts
      newFacts = sFacts <> extend sLimits sRules sFacts
      newCount = countFacts newFacts
      addedFactsCount = newCount - previousCount
  when (newCount >= maxFacts) $ lift $ Left Facts
  when (sIterations >= maxIterations) $ lift $ Left Iterations
  put $ state { sIterations = sIterations + 1
              , sFacts = newFacts
              }
  return addedFactsCount

computeAllFacts :: ComputeState -> Either PureExecError FactGroup
computeAllFacts initState@ComputeState{sRules} = do
  let checkRules = all (all checkRuleHead) sRules
      go = do
        newFacts <- runStep
        if newFacts > 0 then go else gets sFacts
  unless checkRules $ Left BadRule
  evalStateT go initState

checkChecksForGroup :: Limits -> FactGroup -> Natural -> [Check] -> Validation (NonEmpty Check) ()
checkChecksForGroup limits allFacts checksBlockId = traverse_ (checkCheck limits checksBlockId allFacts)

checkChecks :: Limits -> FactGroup -> [(Natural, [Check])] -> Validation (NonEmpty Check) ()
checkChecks limits allFacts = traverse_ (uncurry $ checkChecksForGroup limits allFacts)

checkPolicies :: Limits -> FactGroup -> [Policy] -> Either (Maybe MatchedQuery) MatchedQuery
checkPolicies limits allFacts policies =
  let results = mapMaybe (checkPolicy limits allFacts) policies
  in case results of
       p : _ -> first Just p
       []    -> Left Nothing

runAuthorizerNoTimeout :: Limits -> BlockWithRevocationId -> [BlockWithRevocationId] -> Authorizer -> Either ExecutionError AuthorizationSuccess
runAuthorizerNoTimeout limits authority blocks authorizer = do
  let initState = mkInitState limits authority blocks authorizer
      toExecutionError = \case
        Facts      -> TooManyFacts
        Iterations -> TooManyIterations
        BadRule    -> InvalidRule
  allFacts <- first toExecutionError $ computeAllFacts initState
  let checks = zip [0..] $ bChecks <$> ((fst authority <> vBlock authorizer) : (fst <$> blocks))
      policies = vPolicies authorizer
      checkResults = checkChecks limits allFacts checks
      policyResults = checkPolicies limits allFacts policies
  case (checkResults, policyResults) of
    (Success (), Left Nothing)  -> Left $ ResultError $ NoPoliciesMatched []
    (Success (), Left (Just p)) -> Left $ ResultError $ DenyRuleMatched [] p
    (Failure cs, Left Nothing)  -> Left $ ResultError $ NoPoliciesMatched (NE.toList cs)
    (Failure cs, Left (Just p)) -> Left $ ResultError $ DenyRuleMatched (NE.toList cs) p
    (Failure cs, Right _)       -> Left $ ResultError $ FailedChecks cs
    (Success (), Right p)       -> Right $ AuthorizationSuccess { matchedAllowQuery = p
                                                                , allFacts
                                                                , limits
                                                                }

runAuthorizerWithLimits :: Limits -> BlockWithRevocationId -> [BlockWithRevocationId] -> Authorizer -> IO (Either ExecutionError AuthorizationSuccess)
runAuthorizerWithLimits l@Limits{..} authority blocks v = do
  resultOrTimeout <- timer maxTime $ pure $ runAuthorizerNoTimeout l authority blocks v
  pure $ case resultOrTimeout of
           Nothing -> Left Timeout
           Just r  -> r

runAuthorizer :: BlockWithRevocationId -> [BlockWithRevocationId] -> Authorizer -> IO (Either ExecutionError AuthorizationSuccess)
runAuthorizer = runAuthorizerWithLimits defaultLimits

runFactGeneration :: Limits -> Map Natural (Set Rule) -> FactGroup -> Either PureExecError FactGroup
runFactGeneration sLimits sRules sFacts =
  let initState = ComputeState{sIterations = 0, ..}
  in computeAllFacts initState

queryAuthorizerFacts :: AuthorizationSuccess -> Query -> Set Bindings
queryAuthorizerFacts AuthorizationSuccess{allFacts, limits} q =
  let authorityFacts = fold (Map.lookup (Set.singleton 0) $ getFactGroup allFacts)
      getBindingsForQueryItem QueryItem{qBody,qExpressions} = Set.map snd $
        getBindingsForRuleBody limits (Set.map (mempty,) authorityFacts) qBody qExpressions
  in foldMap getBindingsForQueryItem q

getVariableValues :: (Ord t, FromValue t) => Set Bindings -> Text -> Set t
getVariableValues bindings variableName =
  let mapMaybeS f = foldMap (foldMap Set.singleton . f)
      getVar vars = fromValue =<< vars !? variableName
  in mapMaybeS getVar bindings

getSingleVariableValue :: (Ord t, FromValue t) => Set Bindings -> Text -> Maybe t
getSingleVariableValue bindings variableName =
  let values = getVariableValues bindings variableName
  in case Set.toList values of
       [v] -> Just v
       _   -> Nothing
