{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE RecordWildCards            #-}
{-|
  Module      : Auth.Kailua.Datalog.ScopedExecutor
  Copyright   : updated © Oleg G.Kapranov, 2025
  License     : MIT
  Maintainer  : lugatex@yahoo.com
-}
module Auth.Kailua.Datalog.ScopedExecutor ( AuthorizationSuccess (..)
                                          , BlockWithRevocationId
                                          , FactGroup (..)
                                          , PureExecError (..)
                                          , collectWorld
                                          , getBindings
                                          , getSingleVariableValue
                                          , getVariableValues
                                          , queryAvailableFacts
                                          , queryGeneratedFacts
                                          , runAuthorizer
                                          , runAuthorizerNoTimeout
                                          , runAuthorizerWithLimits
                                          , runFactGeneration
                                          ) where

import           Auth.Kailua.Crypto           (PublicKey)
import           Auth.Kailua.Datalog.AST      ( Authorizer
                                              , Authorizer' (..)
                                              , Block' (..)
                                              , Check
                                              , EvalBlock
                                              , EvalCheck
                                              , EvalPolicy
                                              , EvalRule
                                              , Fact
                                              , FromValue (..)
                                              , Query
                                              , QueryItem' (..)
                                              , Rule' (..)
                                              , ToEvaluation (..)
                                              , checkToEvaluation
                                              , policyToEvaluation
                                              , extractVariables
                                              )
import           Auth.Kailua.Datalog.Executor ( Bindings
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
                                              , fromScopedFacts
                                              , getBindingsForRuleBody
                                              , getFactsForRule
                                              , keepAuthorized'
                                              , toScopedFacts
                                              )
import           Auth.Kailua.Datalog.Parser   (fact)
import           Auth.Kailua.Timer            (timer)
import           Auth.Kailua.Datalog.Types    ( AuthorizationSuccess (..)
                                              , BlockWithRevocationId
                                              , ComputeState (..)
                                              , PureExecError (..)
                                              )
import           Auth.Kailua.Utils            ( foldMapM
                                              , mapMaybeM
                                              )
import           Control.Monad                ( unless
                                              , when
                                              )
import           Control.Monad.State          ( StateT (..)
                                              , evalStateT
                                              , get
                                              , gets
                                              , lift
                                              , put
                                              )
import           Data.Bifunctor               (first)
import           Data.Bitraversable           (bisequence)
import           Data.ByteString              (ByteString)
import           Data.Foldable                (sequenceA_)
import           Data.List                    (genericLength)
import           Data.List.NonEmpty           (NonEmpty)
import qualified Data.List.NonEmpty           as NE
import           Data.Map                     (Map)
import qualified Data.Map                     as Map
import           Data.Map.Strict              ((!?))
import           Data.Set                     (Set)
import qualified Data.Set                     as Set
import           Data.Text                    (Text)
import           Numeric.Natural              (Natural)
import           Validation                   (Validation (..))

getBindings :: AuthorizationSuccess -> Set Bindings
getBindings AuthorizationSuccess{matchedAllowQuery=MatchedQuery{bindings}} = bindings

mkRevocationIdFacts :: BlockWithRevocationId -> [BlockWithRevocationId] -> Set Fact
mkRevocationIdFacts authority blocks =
  let allIds :: [(Int, ByteString)]
      allIds = zip [0..] $ snd' <$> authority : blocks
      snd' (_,b,_) = b
      mkFact (index, rid) = [fact|revocation_id({index}, {rid})|]
  in Set.fromList $ mkFact <$> allIds

extend :: Limits -> Natural -> Map Natural (Set EvalRule) -> FactGroup -> Either String FactGroup
extend l blockCount rules facts =
  let buildFacts :: Natural -> Set EvalRule -> FactGroup -> Either String (Set (Scoped Fact))
      buildFacts ruleBlockId ruleGroup factGroup =
        let extendRule :: EvalRule -> Either String (Set (Scoped Fact))
            extendRule r@Rule{scope} = getFactsForRule l (toScopedFacts $ keepAuthorized' False blockCount factGroup scope ruleBlockId) r
        in foldMapM extendRule ruleGroup

      extendRuleGroup :: Natural -> Set EvalRule -> Either String FactGroup
      extendRuleGroup ruleBlockId ruleGroup =
        let authorizedFacts = facts -- test $ keepAuthorized facts $ Set.fromList [0..ruleBlockId]
            addRuleOrigin = FactGroup . Map.mapKeysWith (<>) (Set.insert ruleBlockId) . getFactGroup
        in addRuleOrigin . fromScopedFacts <$> buildFacts ruleBlockId ruleGroup authorizedFacts

   in foldMapM (uncurry extendRuleGroup) $ Map.toList rules

checkRuleHead :: EvalRule -> Bool
checkRuleHead Rule{rhead, body} =
  let headVars = extractVariables [rhead]
      bodyVars = extractVariables body
  in headVars `Set.isSubsetOf` bodyVars

runStep :: StateT ComputeState (Either PureExecError) Int
runStep = do
  state@ComputeState{sLimits,sFacts,sRules,sBlockCount,sIterations} <- get
  let Limits{maxFacts, maxIterations} = sLimits
      previousCount = countFacts sFacts
      generatedFacts :: Either PureExecError FactGroup
      generatedFacts = first BadExpression $ extend sLimits sBlockCount sRules sFacts
  newFacts <- (sFacts <>) <$> lift generatedFacts
  let newCount = countFacts newFacts
      addedFactsCount = newCount - previousCount
  when (newCount >= maxFacts) $ lift $ Left Facts
  when (sIterations >= maxIterations) $ lift $ Left Iterations
  put $ state { sIterations = sIterations + 1
              , sFacts = newFacts
              }
  pure addedFactsCount

computeAllFacts :: ComputeState -> Either PureExecError FactGroup
computeAllFacts initState@ComputeState{sRules} = do
  let checkRules = all (all checkRuleHead) sRules
      go = do
        newFacts <- runStep
        if newFacts > 0 then go else gets sFacts

  unless checkRules $ Left BadRule
  evalStateT go initState

collectWorld :: Natural -> EvalBlock -> (Map Natural (Set EvalRule), FactGroup)
collectWorld blockId Block{..} =
  let applyScope r@Rule{scope} = r { scope = if null scope then bScope else scope }
  in ( Map.singleton blockId $ Set.map applyScope $ Set.fromList bRules
     , FactGroup $ Map.singleton (Set.singleton blockId) $ Set.fromList bFacts
     )

mkInitState :: Limits -> BlockWithRevocationId -> [BlockWithRevocationId] -> Authorizer -> ComputeState
mkInitState limits authority blocks authorizer =
  let fst' (a,_,_) = a
      trd' (_,_,c) = c
      sBlockCount = 1 + genericLength blocks
      externalKeys = Nothing : (trd' <$> blocks)
      revocationWorld = (mempty, FactGroup $ Map.singleton (Set.singleton sBlockCount) $ mkRevocationIdFacts authority blocks)
      firstBlock = fst' authority
      otherBlocks = fst' <$> blocks
      allBlocks = zip [0..] (firstBlock : otherBlocks) <> [(sBlockCount, vBlock authorizer)]
      (sRules, sFacts) = revocationWorld <> foldMap (uncurry collectWorld . fmap (toEvaluation externalKeys)) allBlocks
   in ComputeState
        { sLimits = limits
        , sRules
        , sBlockCount
        , sIterations = 0
        , sFacts
        }

checkChecksForGroup :: Limits -> Natural -> FactGroup -> Natural -> [EvalCheck] -> Either String (Validation (NonEmpty Check) ())
checkChecksForGroup limits blockCount allFacts checksBlockId =
  fmap sequenceA_ . traverse (checkCheck limits blockCount checksBlockId allFacts)

checkChecks :: Limits -> Natural -> FactGroup -> [(Natural, [EvalCheck])] -> Either String (Validation (NonEmpty Check) ())
checkChecks limits blockCount allFacts =
  fmap sequenceA_ . traverse (uncurry $ checkChecksForGroup limits blockCount allFacts)

checkPolicies :: Limits -> Natural -> FactGroup -> [EvalPolicy] -> Either String (Either (Maybe MatchedQuery) MatchedQuery)
checkPolicies limits blockCount allFacts policies = do
  results <- mapMaybeM (checkPolicy limits blockCount allFacts) policies
  pure $ case results of
           p : _ -> first Just p
           []    -> Left Nothing

runAuthorizerNoTimeout :: Limits -> BlockWithRevocationId -> [BlockWithRevocationId] -> Authorizer -> Either ExecutionError AuthorizationSuccess
runAuthorizerNoTimeout limits authority blocks authorizer = do
  let fst' (a,_,_) = a
      trd' (_,_,c) = c
      blockCount = 1 + genericLength blocks
      externalKeys = Nothing : (trd' <$> blocks)
      (<$$>) = fmap . fmap
      (<$$$>) = fmap . fmap . fmap
      initState = mkInitState limits authority blocks authorizer
      toExecutionError = \case
        Facts      -> TooManyFacts
        Iterations -> TooManyIterations
        BadRule    -> InvalidRule
        BadExpression e -> EvaluationError e
  allFacts <- first toExecutionError $ computeAllFacts initState
  let checks = bChecks <$$> ( zip [0..] (fst' <$> authority : blocks)
                           <> [(blockCount,vBlock authorizer)]
                            )
      policies = vPolicies authorizer
      checkResults = checkChecks limits blockCount allFacts (checkToEvaluation externalKeys <$$$> checks)
      policyResults = checkPolicies limits blockCount allFacts (policyToEvaluation externalKeys <$> policies)
  case bisequence (checkResults, policyResults) of
    Left e                            -> Left $ EvaluationError e
    Right (Success (), Left Nothing)  -> Left $ ResultError $ NoPoliciesMatched []
    Right (Success (), Left (Just p)) -> Left $ ResultError $ DenyRuleMatched [] p
    Right (Failure cs, Left Nothing)  -> Left $ ResultError $ NoPoliciesMatched (NE.toList cs)
    Right (Failure cs, Left (Just p)) -> Left $ ResultError $ DenyRuleMatched (NE.toList cs) p
    Right (Failure cs, Right _)       -> Left $ ResultError $ FailedChecks cs
    Right (Success (), Right p)       -> Right $ AuthorizationSuccess { matchedAllowQuery = p
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

queryAvailableFacts :: [Maybe PublicKey] -> FactGroup -> Limits -> Query -> Either String (Set Bindings)
queryAvailableFacts ePks allFacts limits q =
  let blockCount = genericLength ePks
      getBindingsForQueryItem QueryItem{qBody,qExpressions,qScope} =
        let facts = toScopedFacts $ keepAuthorized' True blockCount allFacts qScope blockCount
        in Set.map snd <$>
           getBindingsForRuleBody limits facts qBody qExpressions
  in foldMapM (getBindingsForQueryItem . toEvaluation ePks) q

queryGeneratedFacts :: [Maybe PublicKey] -> AuthorizationSuccess -> Query -> Either String (Set Bindings)
queryGeneratedFacts ePks AuthorizationSuccess{allFacts, limits} =
  queryAvailableFacts ePks allFacts limits

runFactGeneration :: Limits -> Natural -> Map Natural (Set EvalRule) -> FactGroup -> Either PureExecError FactGroup
runFactGeneration sLimits sBlockCount sRules sFacts =
  let initState = ComputeState{sIterations = 0, ..}
  in computeAllFacts initState
