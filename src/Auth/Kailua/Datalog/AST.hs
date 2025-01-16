{-# LANGUAGE ApplicativeDo              #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-|
  Module      : Auth.Kailua.Datalog.AST
  Copyright   : updated © Oleg G.Kapranov, 2025
  License     : MIT
  Maintainer  : lugatex@yahoo.com
  The Datalog elements
-}
module Auth.Kailua.Datalog.AST ( Authorizer
                               , Authorizer' (..)
                               , AuthorizerElement' (..)
                               , Binary (..)
                               , Block
                               , Block' (..)
                               , BlockElement' (..)
                               , BlockIdType
                               , Check
                               , Check' (..)
                               , CheckKind (..)
                               , DatalogContext (..)
                               , EvalBlock
                               , EvalCheck
                               , EvalPolicy
                               , EvalRule
                               , EvalRuleScope
                               , EvaluationContext (..)
                               , Expression
                               , Expression' (..)
                               , Fact
                               , FromValue (..)
                               , IsWithinSet (..)
                               , Op (..)
                               , PkOrSlice (..)
                               , Policy
                               , Policy'
                               , PolicyType (..)
                               , Predicate
                               , Predicate' (..)
                               , PredicateOrFact (..)
                               , QQTerm
                               , Query
                               , Query'
                               , QueryItem' (..)
                               , Rule
                               , Rule' (..)
                               , RuleScope
                               , RuleScope' (..)
                               , SetType
                               , Slice (..)
                               , SliceType
                               , Term
                               , Term' (..)
                               , ToEvaluation (..)
                               , ToTerm (..)
                               , Unary (..)
                               , Value
                               , VariableType
                               , checkToEvaluation
                               , policyToEvaluation
                               , renderBlock
                               , renderFact
                               , renderRule
                               , elementToAuthorizer
                               , elementToBlock
                               , extractVariables
                               , fromStack
                               , isCheckOne
                               , listPublicKeysInBlock
                               , listSymbolsInBlock
                               , makeQueryItem
                               , makeRule
                               , queryHasNoScope
                               , queryHasNoV4Operators
                               , renderAuthorizer
                               , ruleHasNoScope
                               , ruleHasNoV4Operators
                               , substituteAuthorizer
                               , substituteBlock
                               , substituteCheck
                               , substituteExpression
                               , substituteFact
                               , substitutePTerm
                               , substitutePolicy
                               , substitutePredicate
                               , substituteQuery
                               , substituteRule
                               , substituteTerm
                               , toStack
                               , valueToSetTerm
                               ) where

import Auth.Kailua.Crypto           ( PublicKey
                                    , pkBytes
                                    )
import Auth.Kailua.Datalog.Types    ( Authorizer
                                    , Authorizer' (..)
                                    , AuthorizerElement' (..)
                                    , Binary (..)
                                    , Block
                                    , Block' (..)
                                    , BlockElement' (..)
                                    , BlockIdType
                                    , Check
                                    , Check' (..)
                                    , CheckKind (..)
                                    , DatalogContext (..)
                                    , EvalBlock
                                    , EvalCheck
                                    , EvalPolicy
                                    , EvalRule
                                    , EvalRuleScope
                                    , EvaluationContext (..)
                                    , Expression
                                    , Expression' (..)
                                    , Fact
                                    , FromValue (..)
                                    , IsWithinSet (..)
                                    , Op (..)
                                    , PkOrSlice (..)
                                    , Policy
                                    , Policy'
                                    , PolicyType (..)
                                    , Predicate
                                    , Predicate' (..)
                                    , PredicateOrFact (..)
                                    , QQTerm
                                    , Query
                                    , Query'
                                    , QueryItem' (..)
                                    , Rule
                                    , Rule' (..)
                                    , RuleScope
                                    , RuleScope' (..)
                                    , SetType
                                    , SetValue
                                    , Slice (..)
                                    , SliceType
                                    , Term
                                    , Term' (..)
                                    , ToEvaluation (..)
                                    , ToTerm (..)
                                    , Unary (..)
                                    , Value
                                    , VariableType
                                    , checkToEvaluation
                                    , policyToEvaluation
                                    , renderBlock
                                    , renderFact
                                    , renderId'
                                    , renderRule
                                    )
import           Auth.Kailua.Utils  (encodeHex)
import           Control.Monad      ((<=<))
import           Data.Foldable      (fold)
import           Data.Function      (on)
import           Data.List.NonEmpty ( NonEmpty
                                    , nonEmpty
                                    )
import           Data.Map.Strict    (Map)
import qualified Data.Map.Strict    as Map
import           Data.Maybe         (mapMaybe)
import           Data.Set           (Set)
import qualified Data.Set           as Set
import           Data.Text          ( Text
                                    , intercalate
                                    )
import           Data.Void          (absurd)
import           Validation         ( Validation (..)
                                    , failure
                                    )

valueToSetTerm :: Value -> Maybe (Term' 'WithinSet 'InFact 'Representation)
valueToSetTerm = \case
  LInteger i  -> Just $ LInteger i
  LString i   -> Just $ LString i
  LDate i     -> Just $ LDate i
  LBytes i    -> Just $ LBytes i
  LBool i     -> Just $ LBool i
  TermSet _   -> Nothing
  Variable v  -> absurd v
  Antiquote v -> absurd v

valueToTerm :: Value -> Term
valueToTerm = \case
  LInteger i  -> LInteger i
  LString i   -> LString i
  LDate i     -> LDate i
  LBytes i    -> LBytes i
  LBool i     -> LBool i
  TermSet i   -> TermSet i
  Variable v  -> absurd v
  Antiquote v -> absurd v

listSymbolsInSetValue :: SetValue -> Set.Set Text
listSymbolsInSetValue = \case
  LString  v  -> Set.singleton v
  TermSet   v -> absurd v
  Variable  v -> absurd v
  Antiquote v -> absurd v
  _           -> mempty

listSymbolsInTerm :: Term -> Set.Set Text
listSymbolsInTerm = \case
  LString  v    -> Set.singleton v
  Variable name -> Set.singleton name
  TermSet terms -> foldMap listSymbolsInSetValue terms
  Antiquote v   -> absurd v
  _             -> mempty

listSymbolsInValue :: Value -> Set.Set Text
listSymbolsInValue = \case
  LString  v    -> Set.singleton v
  TermSet terms -> foldMap listSymbolsInSetValue terms
  Variable  v   -> absurd v
  Antiquote v   -> absurd v
  _             -> mempty

listSymbolsInFact :: Fact -> Set.Set Text
listSymbolsInFact Predicate{..} =
     Set.singleton name
  <> foldMap listSymbolsInValue terms

listSymbolsInPredicate :: Predicate -> Set.Set Text
listSymbolsInPredicate Predicate{..} =
     Set.singleton name
  <> foldMap listSymbolsInTerm terms

renderSet :: (SliceType ctx -> Text) -> Set (Term' 'WithinSet 'InFact ctx) -> Text
renderSet slice terms =
  "[" <> intercalate "," (renderId' absurd absurd slice <$> Set.toList terms) <> "]"

renderId :: Term -> Text
renderId = renderId' ("$" <>) (renderSet absurd) absurd

renderPredicate :: Predicate -> Text
renderPredicate Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderId terms) <> ")"

queryHasNoScope :: Query -> Bool
queryHasNoScope = all (Set.null . qScope)

expressionHasNoV4Operators :: Expression -> Bool
expressionHasNoV4Operators = \case
  EBinary BitwiseAnd _ _ -> False
  EBinary BitwiseOr _ _  -> False
  EBinary BitwiseXor _ _ -> False
  EBinary NotEqual   _ _ -> False
  EBinary _ l r -> expressionHasNoV4Operators l && expressionHasNoV4Operators r
  _ -> True

queryHasNoV4Operators :: Query -> Bool
queryHasNoV4Operators =
  all (all expressionHasNoV4Operators . qExpressions)

extractVariables :: [Predicate' 'InPredicate ctx] -> Set Text
extractVariables predicates =
  let keepVariable = \case
        Variable name -> Just name
        _             -> Nothing
      extractVariables' Predicate{terms} = mapMaybe keepVariable terms
  in Set.fromList $ extractVariables' =<< predicates

extractExprVariables :: Expression' ctx -> Set Text
extractExprVariables =
  let keepVariable = \case
        Variable name -> Set.singleton name
        _             -> Set.empty
  in \case
       EValue t       -> keepVariable t
       EUnary _ e     -> extractExprVariables e
       EBinary _ e e' -> ((<>) `on` extractExprVariables) e e'

makeQueryItem :: [Predicate' 'InPredicate ctx] -> [Expression' ctx] -> Set (RuleScope' 'Repr ctx) -> Validation (NonEmpty Text) (QueryItem' 'Repr ctx)
makeQueryItem qBody qExpressions qScope =
  let boundVariables = extractVariables qBody
      exprVariables = foldMap extractExprVariables qExpressions
      unboundVariables = exprVariables `Set.difference` boundVariables
  in case nonEmpty (Set.toList unboundVariables) of
       Nothing -> pure QueryItem{..}
       Just vs -> Failure vs

isCheckOne :: Check' evalCtx ctx -> Bool
isCheckOne Check{cKind} = cKind == One

renderExpression :: Expression -> Text
renderExpression =
  let rOp t e e' = renderExpression e
                 <> " " <> t <> " "
                 <> renderExpression e'
      rm m e e' = renderExpression e
                <> "." <> m <> "("
                <> renderExpression e'
                <> ")"
  in \case
       EValue t                    -> renderId t
       EUnary Negate e             -> "!" <> renderExpression e
       EUnary Parens e             -> "(" <> renderExpression e <> ")"
       EUnary Length e             -> renderExpression e <> ".length()"
       EBinary LessThan e e'       -> rOp "<" e e'
       EBinary GreaterThan e e'    -> rOp ">" e e'
       EBinary LessOrEqual e e'    -> rOp "<=" e e'
       EBinary GreaterOrEqual e e' -> rOp ">=" e e'
       EBinary Equal e e'          -> rOp "==" e e'
       EBinary Contains e e'       -> rm "contains" e e'
       EBinary Prefix e e'         -> rm "starts_with" e e'
       EBinary Suffix e e'         -> rm "ends_with" e e'
       EBinary Regex e e'          -> rm "matches" e e'
       EBinary Intersection e e'   -> rm "intersection" e e'
       EBinary Union e e'          -> rm "union" e e'
       EBinary Add e e'            -> rOp "+" e e'
       EBinary Sub e e'            -> rOp "-" e e'
       EBinary Mul e e'            -> rOp "*" e e'
       EBinary Div e e'            -> rOp "/" e e'
       EBinary And e e'            -> rOp "&&" e e'
       EBinary Or e e'             -> rOp "||" e e'
       EBinary BitwiseAnd e e'     -> rOp "&" e e'
       EBinary BitwiseOr e e'      -> rOp "|" e e'
       EBinary BitwiseXor e e'     -> rOp "^" e e'
       EBinary NotEqual e e'       -> rOp "!=" e e'

renderRuleScope :: Set RuleScope -> Text
renderRuleScope =
  let renderScopeElem = \case
        OnlyAuthority -> "authority"
        Previous      -> "previous"
        BlockId bs    -> "ed25519/" <> encodeHex (pkBytes bs)
  in intercalate ", " . Set.toList . Set.map renderScopeElem

renderQueryItem :: QueryItem' 'Repr 'Representation -> Text
renderQueryItem QueryItem{..} =
  intercalate ",\n" (fold
    [ renderPredicate <$> qBody
    , renderExpression <$> qExpressions
    ])
  <> if null qScope then "" else " trusting " <> renderRuleScope qScope

renderPolicy :: Policy -> Text
renderPolicy (pType, query) =
  let prefix = case pType of
        Allow -> "allow if "
        Deny  -> "deny if "
  in prefix <> intercalate " or \n" (renderQueryItem <$> query) <> ";"

listSymbolsInExpression :: Expression -> Set.Set Text
listSymbolsInExpression = \case
  EValue t       -> listSymbolsInTerm t
  EUnary _ e     -> listSymbolsInExpression e
  EBinary _ e e' -> foldMap listSymbolsInExpression [e, e']

listSymbolsInQueryItem :: QueryItem' evalCtx 'Representation -> Set.Set Text
listSymbolsInQueryItem QueryItem{..} =
     Set.singleton "query"
  <> foldMap listSymbolsInPredicate qBody
  <> foldMap listSymbolsInExpression qExpressions

listSymbolsInCheck :: Check -> Set.Set Text
listSymbolsInCheck =
  foldMap listSymbolsInQueryItem . cQueries

listPublicKeysInScope :: Set.Set RuleScope -> Set.Set PublicKey
listPublicKeysInScope = foldMap $
  \case BlockId pk -> Set.singleton pk
        _          -> Set.empty

listPublicKeysInQueryItem :: QueryItem' 'Repr 'Representation -> Set.Set PublicKey
listPublicKeysInQueryItem QueryItem{qScope} =
  listPublicKeysInScope qScope

listPublicKeysInCheck :: Check -> Set.Set PublicKey
listPublicKeysInCheck = foldMap listPublicKeysInQueryItem . cQueries

ruleHasNoScope :: Rule -> Bool
ruleHasNoScope Rule{scope} = Set.null scope

ruleHasNoV4Operators :: Rule -> Bool
ruleHasNoV4Operators Rule{expressions} =
  all expressionHasNoV4Operators expressions

listSymbolsInRule :: Rule -> Set.Set Text
listSymbolsInRule Rule{..} =
     listSymbolsInPredicate rhead
  <> foldMap listSymbolsInPredicate body
  <> foldMap listSymbolsInExpression expressions

listPublicKeysInRule :: Rule -> Set.Set PublicKey
listPublicKeysInRule Rule{scope} = listPublicKeysInScope scope

makeRule :: Predicate' 'InPredicate ctx -> [Predicate' 'InPredicate ctx] -> [Expression' ctx] -> Set (RuleScope' 'Repr ctx) -> Validation (NonEmpty Text) (Rule' 'Repr ctx)
makeRule rhead body expressions scope =
  let boundVariables = extractVariables body
      exprVariables = foldMap extractExprVariables expressions
      headVariables = extractVariables [rhead]
      unboundVariables = (headVariables `Set.union` exprVariables) `Set.difference` boundVariables
  in case nonEmpty (Set.toList unboundVariables) of
       Nothing -> pure Rule{..}
       Just vs -> Failure vs

fromStack :: [Op] -> Either String Expression
fromStack =
  let go stack []                    = Right stack
      go stack        (VOp t : rest) = go (EValue t : stack) rest
      go (e:stack)    (UOp o : rest) = go (EUnary o e : stack) rest
      go []           (UOp _ : _)    = Left "Empty stack on unary op"
      go (e:e':stack) (BOp o : rest) = go (EBinary o e' e : stack) rest
      go [_]          (BOp _ : _)    = Left "Unary stack on binary op"
      go []           (BOp _ : _)    = Left "Empty stack on binary op"
      final []  = Left "Empty stack"
      final [x] = Right x
      final _   = Left "Stack containing more than one element"
  in final <=< go []

toStack :: Expression -> [Op]
toStack expr =
  let go e s = case e of
        EValue t      -> VOp t : s
        EUnary o i    -> go i $ UOp o : s
        EBinary o l r -> go l $ go r $ BOp o : s
  in go expr []

listSymbolsInBlock :: Block -> Set.Set Text
listSymbolsInBlock Block {..} = fold
  [ foldMap listSymbolsInRule bRules
  , foldMap listSymbolsInFact bFacts
  , foldMap listSymbolsInCheck bChecks
  ]

listPublicKeysInBlock :: Block -> Set.Set PublicKey
listPublicKeysInBlock Block{..} = fold
  [ foldMap listPublicKeysInRule bRules
  , foldMap listPublicKeysInCheck bChecks
  , listPublicKeysInScope bScope
  ]

renderAuthorizer :: Authorizer -> Text
renderAuthorizer Authorizer{..} =
  renderBlock vBlock <> "\n" <>
  intercalate "\n" (renderPolicy <$> vPolicies)

elementToBlock :: BlockElement' evalCtx ctx -> Block' evalCtx ctx
elementToBlock = \case
   BlockRule r  -> Block [r] [] [] Nothing Set.empty
   BlockFact f  -> Block [] [f] [] Nothing Set.empty
   BlockCheck c -> Block [] [] [c] Nothing Set.empty
   BlockComment -> mempty

elementToAuthorizer :: AuthorizerElement' evalCtx ctx -> Authorizer' evalCtx ctx
elementToAuthorizer = \case
  AuthorizerPolicy p -> Authorizer [p] mempty
  BlockElement be    -> Authorizer [] (elementToBlock be)

substituteSetTerm :: Map Text Value -> Term' 'WithinSet 'InFact 'WithSlices -> Validation (NonEmpty Text) (Term' 'WithinSet 'InFact 'Representation)
substituteSetTerm termMapping = \case
  LInteger i  -> pure $ LInteger i
  LString i   -> pure $ LString i
  LDate i     -> pure $ LDate i
  LBytes i    -> pure $ LBytes i
  LBool i     -> pure $ LBool i
  TermSet v   -> absurd v
  Variable v  -> absurd v
  Antiquote (Slice v) ->
    let setTerm = valueToSetTerm =<< termMapping Map.!? v
    in maybe (failure v) pure setTerm

substitutePTerm :: Map Text Value -> Term' 'NotWithinSet 'InPredicate 'WithSlices -> Validation (NonEmpty Text) (Term' 'NotWithinSet 'InPredicate 'Representation)
substitutePTerm termMapping = \case
  LInteger i  -> pure $ LInteger i
  LString i   -> pure $ LString i
  LDate i     -> pure $ LDate i
  LBytes i    -> pure $ LBytes i
  LBool i     -> pure $ LBool i
  TermSet i   ->
    TermSet . Set.fromList <$> traverse (substituteSetTerm termMapping) (Set.toList i)
  Variable i  -> pure $ Variable i
  Antiquote (Slice v) -> maybe (failure v) (pure . valueToTerm) $ termMapping Map.!? v

substitutePredicate :: Map Text Value -> Predicate' 'InPredicate 'WithSlices -> Validation (NonEmpty Text) (Predicate' 'InPredicate 'Representation)
substitutePredicate termMapping Predicate{..} = do
  newTerms <- traverse (substitutePTerm termMapping) terms
  pure Predicate{ terms = newTerms, .. }

substituteExpression :: Map Text Value -> Expression' 'WithSlices -> Validation (NonEmpty Text) Expression
substituteExpression termMapping = \case
  EValue v -> EValue <$> substitutePTerm termMapping v
  EUnary op e -> EUnary op <$> substituteExpression termMapping e
  EBinary op e e' -> EBinary op <$> substituteExpression termMapping e
                                <*> substituteExpression termMapping e'

substituteScope :: Map Text PublicKey -> RuleScope' 'Repr 'WithSlices -> Validation (NonEmpty Text) RuleScope
substituteScope keyMapping = \case
    OnlyAuthority -> pure OnlyAuthority
    Previous      -> pure Previous
    BlockId (Pk pk) -> pure $ BlockId pk
    BlockId (PkSlice n) -> maybe (failure n) (pure . BlockId) $ keyMapping Map.!? n

substituteQuery :: Map Text Value-> Map Text PublicKey -> QueryItem' 'Repr 'WithSlices -> Validation (NonEmpty Text) (QueryItem' 'Repr 'Representation)
substituteQuery termMapping keyMapping QueryItem{..} = do
  newBody <- traverse (substitutePredicate termMapping) qBody
  newExpressions <- traverse (substituteExpression termMapping) qExpressions
  newScope <- Set.fromList <$> traverse (substituteScope keyMapping) (Set.toList qScope)
  pure QueryItem{
    qBody = newBody,
    qExpressions = newExpressions,
    qScope = newScope
  }

substitutePolicy :: Map Text Value -> Map Text PublicKey -> Policy' 'Repr 'WithSlices -> Validation (NonEmpty Text) Policy
substitutePolicy termMapping keyMapping =
  traverse (traverse (substituteQuery termMapping keyMapping))

substituteRule :: Map Text Value -> Map Text PublicKey -> Rule' 'Repr 'WithSlices -> Validation (NonEmpty Text) Rule
substituteRule termMapping keyMapping Rule{..} = do
  newHead <- substitutePredicate termMapping rhead
  newBody <- traverse (substitutePredicate termMapping) body
  newExpressions <- traverse (substituteExpression termMapping) expressions
  newScope <- Set.fromList <$> traverse (substituteScope keyMapping) (Set.toList scope)
  pure Rule{
    rhead = newHead,
    body = newBody,
    expressions = newExpressions,
    scope = newScope
  }

substituteTerm :: Map Text Value -> Term' 'NotWithinSet 'InFact 'WithSlices -> Validation (NonEmpty Text) Value
substituteTerm termMapping = \case
  LInteger i  -> pure $ LInteger i
  LString i   -> pure $ LString i
  LDate i     -> pure $ LDate i
  LBytes i    -> pure $ LBytes i
  LBool i     -> pure $ LBool i
  TermSet i   ->
    TermSet . Set.fromList <$> traverse (substituteSetTerm termMapping) (Set.toList i)
  Variable v  -> absurd v
  Antiquote (Slice v) -> maybe (failure v) pure $ termMapping Map.!? v

substituteFact :: Map Text Value -> Predicate' 'InFact 'WithSlices -> Validation (NonEmpty Text) Fact
substituteFact termMapping Predicate{..} = do
  newTerms <- traverse (substituteTerm termMapping) terms
  pure Predicate{ terms = newTerms, .. }

substituteCheck :: Map Text Value -> Map Text PublicKey -> Check' 'Repr 'WithSlices -> Validation (NonEmpty Text) Check
substituteCheck termMapping keyMapping Check{..} = do
  newQueries <- traverse (substituteQuery termMapping keyMapping) cQueries
  pure Check{cQueries = newQueries, ..}

substituteBlock :: Map Text Value -> Map Text PublicKey -> Block' 'Repr 'WithSlices -> Validation (NonEmpty Text) Block
substituteBlock termMapping keyMapping Block{..} = do
  newRules <-  traverse (substituteRule termMapping keyMapping) bRules
  newFacts <-  traverse (substituteFact termMapping) bFacts
  newChecks <- traverse (substituteCheck termMapping keyMapping) bChecks
  newScope <- Set.fromList <$> traverse (substituteScope keyMapping) (Set.toList bScope)
  pure Block{
    bRules = newRules,
    bFacts = newFacts,
    bChecks = newChecks,
    bScope = newScope,
    ..}

substituteAuthorizer :: Map Text Value -> Map Text PublicKey -> Authorizer' 'Repr 'WithSlices -> Validation (NonEmpty Text) Authorizer
substituteAuthorizer termMapping keyMapping Authorizer{..} = do
  newPolicies <- traverse (substitutePolicy termMapping keyMapping) vPolicies
  newBlock <- substituteBlock termMapping keyMapping vBlock
  pure Authorizer{
    vPolicies = newPolicies,
    vBlock = newBlock
  }
