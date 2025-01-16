{-# LANGUAGE CPP                        #-}
{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveLift                 #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE LambdaCase                 #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RecordWildCards            #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}
{-|
  Module      : Auth.Kailua.Datalog.Types
  Copyright   : updated © Oleg G.Kapranov, 2025
  License     : MIT
  Maintainer  : lugatex@yahoo.com
  The Datalog Types
-}
module Auth.Kailua.Datalog.Types ( Authorizer
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
                                 , Parser
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
                                 , SemanticError (..)
                                 , SetType
                                 , SetValue
                                 , Slice (..)
                                 , SliceType
                                 , Span
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
                                 , renderBlockIds
                                 , renderFact
                                 , renderId'
                                 , renderRule
                                 ) where

import           Auth.Kailua.Crypto         ( PublicKey
                                            , pkBytes
                                            )
import           Auth.Kailua.Utils          (encodeHex)
import           Data.ByteString            (ByteString)
import           Data.Foldable              ( fold
                                            , toList
                                            )
import           Data.Int                   (Int64)
import           Data.Map.Strict            (Map)
import qualified Data.Map.Strict            as Map
import           Data.Set                   (Set)
import qualified Data.Set                   as Set
import           Data.String                (IsString)
import           Data.Text                  ( Text
                                            , intercalate
                                            , pack
                                            , unpack
                                            )
import           Data.Time                  ( UTCTime
                                            , defaultTimeLocale
                                            , formatTime
                                            )
import           Data.Void                  ( Void
                                            , absurd
                                            )
import           Instances.TH.Lift          ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Syntax
import           Numeric.Natural            (Natural)

import Text.Megaparsec
import Data.List.NonEmpty                       (NonEmpty)
import qualified Data.List.NonEmpty             as NE

data IsWithinSet = NotWithinSet | WithinSet
data DatalogContext = WithSlices | Representation
data EvaluationContext = Repr | Eval
data PredicateOrFact = InPredicate | InFact
data PkOrSlice = PkSlice Text | Pk PublicKey deriving (Eq, Show, Ord)
data CheckKind = One | All deriving (Eq, Show, Ord, Lift)

data Term' (inSet :: IsWithinSet) (pof :: PredicateOrFact) (ctx :: DatalogContext) =
    Variable (VariableType inSet pof)
  | LInteger Int64
  | LString Text
  | LDate UTCTime
  | LBytes ByteString
  | LBool Bool
  | Antiquote (SliceType ctx)
  | TermSet (SetType inSet ctx)

deriving instance ( Eq (VariableType inSet pof)
                  , Eq (SliceType ctx)
                  , Eq (SetType inSet ctx)
                  ) => Eq (Term' inSet pof ctx)

deriving instance ( Ord (VariableType inSet pof)
                  , Ord (SliceType ctx)
                  , Ord (SetType inSet ctx)
                  ) => Ord (Term' inSet pof ctx)

deriving instance ( Show (VariableType inSet pof)
                  , Show (SliceType ctx)
                  , Show (SetType inSet ctx)
                  ) => Show (Term' inSet pof ctx)

data Predicate' (pof :: PredicateOrFact) (ctx :: DatalogContext) = Predicate
  { name  :: Text
  , terms :: [Term' 'NotWithinSet pof ctx]
  }

deriving instance ( Eq (Term' 'NotWithinSet pof ctx)
                  ) => Eq (Predicate' pof ctx)
deriving instance ( Ord (Term' 'NotWithinSet pof ctx)
                  ) => Ord (Predicate' pof ctx)
deriving instance ( Show (Term' 'NotWithinSet pof ctx)
                  ) => Show (Predicate' pof ctx)

deriving instance Lift (Term' 'NotWithinSet pof ctx) => Lift (Predicate' pof ctx)

data QueryItem' evalCtx ctx = QueryItem
  { qBody        :: [Predicate' 'InPredicate ctx]
  , qExpressions :: [Expression' ctx]
  , qScope       :: Set (RuleScope' evalCtx ctx)
  }

deriving instance ( Eq (Predicate' 'InPredicate ctx)
                  , Eq (Expression' ctx)
                  , Eq (RuleScope' evalCtx ctx)
                  ) => Eq (QueryItem' evalCtx ctx)
deriving instance ( Ord (Predicate' 'InPredicate ctx)
                  , Ord (Expression' ctx)
                  , Ord (RuleScope' evalCtx ctx)
                  ) => Ord (QueryItem' evalCtx ctx)
deriving instance ( Show (Predicate' 'InPredicate ctx)
                  , Show (Expression' ctx)
                  , Show (RuleScope' evalCtx ctx)
                  ) => Show (QueryItem' evalCtx ctx)
deriving instance ( Lift (Predicate' 'InPredicate ctx)
                  , Lift (Expression' ctx)
                  , Lift (RuleScope' evalCtx ctx)
                  ) => Lift (QueryItem' evalCtx ctx)

data Check' evalCtx ctx = Check
  { cQueries :: Query' evalCtx ctx
  , cKind    :: CheckKind
  }

deriving instance ( Eq (QueryItem' evalCtx ctx)
                  ) => Eq (Check' evalCtx ctx)
deriving instance ( Ord (QueryItem' evalCtx ctx)
                  ) => Ord (Check' evalCtx ctx)
deriving instance ( Show (QueryItem' evalCtx ctx)
                  ) => Show (Check' evalCtx ctx)
deriving instance ( Lift (QueryItem' evalCtx ctx)
                  ) => Lift (Check' evalCtx ctx)

data PolicyType = Allow | Deny deriving (Eq, Show, Ord, Lift)

data RuleScope' (evalCtx :: EvaluationContext) (ctx :: DatalogContext) =
    OnlyAuthority
  | Previous
  | BlockId (BlockIdType evalCtx ctx)

deriving instance Eq   (BlockIdType evalCtx ctx) => Eq   (RuleScope' evalCtx ctx)
deriving instance Ord  (BlockIdType evalCtx ctx) => Ord  (RuleScope' evalCtx ctx)
deriving instance Show (BlockIdType evalCtx ctx) => Show (RuleScope' evalCtx ctx)
deriving instance Lift (BlockIdType evalCtx ctx) => Lift (RuleScope' evalCtx ctx)

data Rule' evalCtx ctx = Rule
  { rhead       :: Predicate' 'InPredicate ctx
  , body        :: [Predicate' 'InPredicate ctx]
  , expressions :: [Expression' ctx]
  , scope       :: Set (RuleScope' evalCtx ctx)
  }

deriving instance ( Eq (Predicate' 'InPredicate ctx)
                  , Eq (Expression' ctx)
                  , Eq (RuleScope' evalCtx ctx)
                  ) => Eq (Rule' evalCtx ctx)
deriving instance ( Ord (Predicate' 'InPredicate ctx)
                  , Ord (Expression' ctx)
                  , Ord (RuleScope' evalCtx ctx)
                  ) => Ord (Rule' evalCtx ctx)
deriving instance ( Show (Predicate' 'InPredicate ctx)
                  , Show (Expression' ctx)
                  , Show (RuleScope' evalCtx ctx)
                  ) => Show (Rule' evalCtx ctx)
deriving instance ( Lift (Predicate' 'InPredicate ctx)
                  , Lift (Expression' ctx)
                  , Lift (RuleScope' evalCtx ctx)
                  ) => Lift (Rule' evalCtx ctx)

data Unary = Negate | Parens | Length deriving (Eq, Ord, Show, Lift)

data Binary =
    LessThan
  | GreaterThan
  | LessOrEqual
  | GreaterOrEqual
  | Equal
  | Contains
  | Prefix
  | Suffix
  | Regex
  | Add
  | Sub
  | Mul
  | Div
  | And
  | Or
  | Intersection
  | Union
  | BitwiseAnd
  | BitwiseOr
  | BitwiseXor
  | NotEqual
  deriving (Eq, Ord, Show, Lift)

data Expression' (ctx :: DatalogContext) =
    EValue (Term' 'NotWithinSet 'InPredicate ctx)
  | EUnary Unary (Expression' ctx)
  | EBinary Binary (Expression' ctx) (Expression' ctx)

deriving instance Eq   (Term' 'NotWithinSet 'InPredicate ctx) => Eq   (Expression' ctx)
deriving instance Ord  (Term' 'NotWithinSet 'InPredicate ctx) => Ord  (Expression' ctx)
deriving instance Lift (Term' 'NotWithinSet 'InPredicate ctx) => Lift (Expression' ctx)
deriving instance Show (Term' 'NotWithinSet 'InPredicate ctx) => Show (Expression' ctx)

data Op = VOp Term | UOp Unary | BOp Binary

data Block' (evalCtx :: EvaluationContext) (ctx :: DatalogContext) = Block
  { bRules   :: [Rule' evalCtx ctx]
  , bFacts   :: [Predicate' 'InFact ctx]
  , bChecks  :: [Check' evalCtx ctx]
  , bContext :: Maybe Text
  , bScope   :: Set (RuleScope' evalCtx ctx)
  }

deriving instance ( Eq (Predicate' 'InFact ctx)
                  , Eq (Rule' evalCtx ctx)
                  , Eq (QueryItem' evalCtx ctx)
                  , Eq (RuleScope' evalCtx ctx)
                  ) => Eq (Block' evalCtx ctx)
deriving instance ( Lift (Predicate' 'InFact ctx)
                  , Lift (Rule' evalCtx ctx)
                  , Lift (QueryItem' evalCtx ctx)
                  , Lift (RuleScope' evalCtx ctx)
                  ) => Lift (Block' evalCtx ctx)

data Authorizer' (evalCtx :: EvaluationContext) (ctx :: DatalogContext) = Authorizer
  { vPolicies :: [Policy' evalCtx ctx]
  , vBlock    :: Block' evalCtx ctx
  }

deriving instance ( Eq (Block' evalCtx ctx)
                  , Eq (QueryItem' evalCtx ctx)
                  ) => Eq (Authorizer' evalCtx ctx)

deriving instance ( Show (Block' evalCtx ctx)
                  , Show (QueryItem' evalCtx ctx)
                  ) => Show (Authorizer' evalCtx ctx)

deriving instance ( Lift (Block' evalCtx ctx)
                  , Lift (QueryItem' evalCtx ctx)
                  ) => Lift (Authorizer' evalCtx ctx)

data BlockElement' evalCtx ctx
  = BlockFact (Predicate' 'InFact ctx)
  | BlockRule (Rule' evalCtx ctx)
  | BlockCheck (Check' evalCtx ctx)
  | BlockComment

deriving instance ( Show (Predicate' 'InFact ctx)
                  , Show (Rule' evalCtx ctx)
                  , Show (QueryItem' evalCtx ctx)
                  ) => Show (BlockElement' evalCtx ctx)

data AuthorizerElement' evalCtx ctx
  = AuthorizerPolicy (Policy' evalCtx ctx)
  | BlockElement (BlockElement' evalCtx ctx)

deriving instance ( Show (Predicate' 'InFact ctx)
                  , Show (Rule' evalCtx ctx)
                  , Show (QueryItem' evalCtx ctx)
                  ) => Show (AuthorizerElement' evalCtx ctx)

data SemanticError =
    VarInFact Span
  | VarInSet  Span
  | NestedSet Span
  | InvalidBs Text Span
  | InvalidPublicKey Text Span
  | UnboundVariables (NonEmpty Text) Span
  | PreviousInAuthorizer Span
  deriving stock (Eq, Ord)

newtype Slice = Slice Text deriving newtype (Eq, Show, Ord, IsString)

type family VariableType (inSet :: IsWithinSet) (pof :: PredicateOrFact)
  where
    VariableType 'NotWithinSet 'InPredicate = Text
    VariableType inSet          pof         = Void

type family SliceType (ctx :: DatalogContext)
  where
    SliceType 'Representation = Void
    SliceType 'WithSlices     = Slice

type family SetType (inSet :: IsWithinSet) (ctx :: DatalogContext)
  where
    SetType 'NotWithinSet ctx = Set (Term' 'WithinSet 'InFact ctx)
    SetType 'WithinSet    ctx = Void

type family BlockIdType (evalCtx :: EvaluationContext) (ctx :: DatalogContext)
  where
    BlockIdType 'Repr 'WithSlices     = PkOrSlice
    BlockIdType 'Repr 'Representation = PublicKey
    BlockIdType 'Eval 'Representation = (Set Natural, PublicKey)

type Term = Term' 'NotWithinSet 'InPredicate 'Representation
type QQTerm = Term' 'NotWithinSet 'InPredicate 'WithSlices
type Value = Term' 'NotWithinSet 'InFact 'Representation
type Predicate = Predicate' 'InPredicate 'Representation
type Fact = Predicate' 'InFact 'Representation
type Query' evalCtx ctx = [QueryItem' evalCtx ctx]
type Query = Query' 'Repr 'Representation
type Check = Check' 'Repr 'Representation
type EvalCheck = Check' 'Eval 'Representation
type Policy' evalCtx ctx = (PolicyType, Query' evalCtx ctx)
type Policy = Policy' 'Repr 'Representation
type EvalPolicy = Policy' 'Eval 'Representation
type RuleScope = RuleScope' 'Repr 'Representation
type EvalRuleScope = RuleScope' 'Eval 'Representation
type Rule = Rule' 'Repr 'Representation
type EvalRule = Rule' 'Eval 'Representation
type Expression = Expression' 'Representation
type Block = Block' 'Repr 'Representation
type EvalBlock = Block' 'Eval 'Representation
type Authorizer = Authorizer' 'Repr 'Representation
type SetValue = Term' 'WithinSet 'InFact 'Representation
type Parser = Parsec SemanticError Text
type Span = (Int, Int)

class ToTerm t inSet pof
  where
    toTerm :: t -> Term' inSet pof 'Representation

class FromValue t
  where
    fromValue :: Value -> Maybe t

class ToEvaluation elem where
  toEvaluation :: [Maybe PublicKey] -> elem 'Repr 'Representation -> elem 'Eval 'Representation
  toRepresentation :: elem 'Eval 'Representation -> elem 'Repr 'Representation

instance Lift Slice where
  lift (Slice name) = [| toTerm $(varE $ mkName $ unpack name) |]
#if MIN_VERSION_template_haskell(2,17,0)
  liftTyped = liftCode . unsafeTExpCoerce . lift
#else
  liftTyped = unsafeTExpCoerce . lift
#endif

instance Lift PkOrSlice where
  lift (PkSlice name) = [| $(varE $ mkName $ unpack name) |]
  lift (Pk pk)        = [| pk |]
#if MIN_VERSION_template_haskell(2,17,0)
  liftTyped = liftCode . unsafeTExpCoerce . lift
#else
  liftTyped = unsafeTExpCoerce . lift
#endif

instance  ( Lift (VariableType inSet pof)
          , Lift (SetType inSet ctx)
          , Lift (SliceType ctx)
          )
         => Lift (Term' inSet pof ctx)
  where
    lift (Variable n)    = [| Variable n |]
    lift (LInteger i)    = [| LInteger i |]
    lift (LString s)     = [| LString s |]
    lift (LBytes bs)     = [| LBytes bs |]
    lift (LBool b)       = [| LBool  b |]
    lift (TermSet terms) = [| TermSet terms |]
    lift (LDate t)       = [| LDate (read $(lift $ show t)) |]
    lift (Antiquote s)   = [| s |]
#if MIN_VERSION_template_haskell(2,17,0)
    liftTyped = liftCode . unsafeTExpCoerce . lift
#else
    liftTyped = unsafeTExpCoerce . lift
#endif

instance ToTerm Int inSet pof
  where
    toTerm = LInteger . fromIntegral

instance FromValue Int
  where
    fromValue (LInteger v) = Just $ fromIntegral v
    fromValue _            = Nothing

instance ToTerm Integer inSet pof
  where
    toTerm = LInteger . fromIntegral

instance FromValue Integer
  where
    fromValue (LInteger v) = Just (fromIntegral v)
    fromValue _            = Nothing

instance ToTerm Text inSet pof
  where
    toTerm = LString

instance FromValue Text
  where
    fromValue (LString t) = Just t
    fromValue _           = Nothing

instance ToTerm Bool inSet pof
  where
    toTerm = LBool

instance FromValue Bool
  where
    fromValue (LBool b) = Just b
    fromValue _         = Nothing

instance ToTerm ByteString inSet pof
  where
    toTerm = LBytes

instance FromValue ByteString
  where
    fromValue (LBytes bs) = Just bs
    fromValue _           = Nothing

instance ToTerm UTCTime inSet pof
  where
    toTerm = LDate

instance FromValue UTCTime
  where
    fromValue (LDate t) = Just t
    fromValue _         = Nothing

instance (Foldable f, ToTerm a 'WithinSet 'InFact) => ToTerm (f a) 'NotWithinSet pof
  where
    toTerm vs = TermSet . Set.fromList $ toTerm <$> toList vs

instance FromValue Value
  where
    fromValue = Just

instance Show Block where
  show = unpack . renderBlock

instance Semigroup (Block' evalCtx ctx) where
  b1 <> b2 = Block { bRules = bRules b1 <> bRules b2
                   , bFacts = bFacts b1 <> bFacts b2
                   , bChecks = bChecks b1 <> bChecks b2
                   , bContext = bContext b2 <|> bContext b1
                   , bScope = if null (bScope b1)
                              then bScope b2
                              else bScope b1
                   }

instance Monoid (Block' evalCtx ctx) where
  mempty = Block { bRules = []
                 , bFacts = []
                 , bChecks = []
                 , bContext = Nothing
                 , bScope = Set.empty
                 }

instance Semigroup (Authorizer' evalCtx ctx) where
  v1 <> v2 = Authorizer { vPolicies = vPolicies v1 <> vPolicies v2
                        , vBlock = vBlock v1 <> vBlock v2
                        }
instance Monoid (Authorizer' evalCtx ctx) where
  mempty = Authorizer { vPolicies = []
                    , vBlock = mempty
                    }

instance ToEvaluation Rule' where
  toEvaluation ePks r = r { scope = translateScope ePks $ scope r }
  toRepresentation r  = r { scope = renderBlockIds $ scope r }

instance ToEvaluation QueryItem' where
  toEvaluation ePks qi = qi{ qScope = translateScope ePks $ qScope qi}
  toRepresentation qi  = qi { qScope = renderBlockIds $ qScope qi}

instance ToEvaluation Check' where
  toEvaluation ePks c =  c { cQueries = fmap (toEvaluation ePks) (cQueries c) }
  toRepresentation c  =  c { cQueries = fmap toRepresentation (cQueries c) }

instance ToEvaluation Block' where
  toEvaluation ePks b = b
    { bScope = translateScope ePks $ bScope b
    , bRules = toEvaluation ePks <$> bRules b
    , bChecks = checkToEvaluation ePks <$> bChecks b
    }
  toRepresentation b  = b
    { bScope = renderBlockIds $ bScope b
    , bRules = toRepresentation <$> bRules b
    , bChecks = toRepresentation <$> bChecks b
    }

instance ToEvaluation Authorizer' where
  toEvaluation ePks a = a
    { vBlock = toEvaluation ePks (vBlock a)
    , vPolicies = policyToEvaluation ePks <$> vPolicies a
    }
  toRepresentation a = a
    { vBlock = toRepresentation (vBlock a)
    , vPolicies = fmap (fmap toRepresentation) <$> vPolicies a
    }

instance ShowErrorComponent SemanticError where
  showErrorComponent = \case
    VarInFact _            -> "Variables can't appear in a fact"
    VarInSet  _            -> "Variables can't appear in a set"
    NestedSet _            -> "Sets cannot be nested"
    InvalidBs e _          -> "Invalid bytestring literal: " <> unpack e
    InvalidPublicKey e _   -> "Invalid public key: " <> unpack e
    UnboundVariables e _   -> "Unbound variables: " <> unpack (intercalate ", " $ NE.toList e)
    PreviousInAuthorizer _ -> "'previous' can't appear in an authorizer scope"

checkToEvaluation :: [Maybe PublicKey] -> Check -> EvalCheck
checkToEvaluation = toEvaluation

policyToEvaluation :: [Maybe PublicKey] -> Policy -> EvalPolicy
policyToEvaluation ePks = fmap (fmap (toEvaluation ePks))

translateScope :: [Maybe PublicKey] -> Set RuleScope -> Set EvalRuleScope
translateScope ePks =
  let indexedPks :: Map PublicKey (Set Natural)
      indexedPks =
        let makeEntry (Just bPk, bId) = [(bPk, Set.singleton bId)]
            makeEntry _               = []
        in Map.fromListWith (<>) $ foldMap makeEntry $ zip ePks [0..]
      translateElem = \case
        Previous      -> Previous
        OnlyAuthority -> OnlyAuthority
        BlockId bPk   -> BlockId (fold $ Map.lookup bPk indexedPks, bPk)
  in Set.map translateElem

renderBlockIds :: Set EvalRuleScope -> Set RuleScope
renderBlockIds =
  let renderElem = \case
        Previous         -> Previous
        OnlyAuthority    -> OnlyAuthority
        BlockId (_, ePk) -> BlockId ePk
  in Set.map renderElem

renderId' :: (VariableType inSet pof -> Text) -> (SetType inSet ctx -> Text) -> (SliceType ctx -> Text) -> Term' inSet pof ctx -> Text
renderId' var set slice = \case
  Variable name -> var name
  LInteger int  -> pack $ show int
  LString str   -> pack $ show str
  LDate time    -> pack $ formatTime defaultTimeLocale "%FT%T%Q%Ez" time
  LBytes bs     -> "hex:" <> encodeHex bs
  LBool True    -> "true"
  LBool False   -> "false"
  TermSet terms -> set terms
  Antiquote v   -> slice v

renderSet :: (SliceType ctx -> Text) -> Set (Term' 'WithinSet 'InFact ctx) -> Text
renderSet slice terms =
  "[" <> intercalate "," (renderId' absurd absurd slice <$> Set.toList terms) <> "]"

renderFactId :: Term' 'NotWithinSet 'InFact 'Representation -> Text
renderFactId = renderId' absurd (renderSet absurd) absurd

renderFact :: Fact -> Text
renderFact Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderFactId terms) <> ")"

renderId :: Term -> Text
renderId = renderId' ("$" <>) (renderSet absurd) absurd

renderPredicate :: Predicate -> Text
renderPredicate Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderId terms) <> ")"

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

renderCheck :: Check -> Text
renderCheck Check{..} =
  let kindToken = case cKind of
        One -> "if"
        All -> "all"
  in "check " <> kindToken <> " " <> intercalate "\n or " (renderQueryItem <$> cQueries)

renderRule :: Rule -> Text
renderRule Rule{rhead,body,expressions,scope} =
     renderPredicate rhead <> " <- "
  <> intercalate ", " (fmap renderPredicate body <> fmap renderExpression expressions)
  <> if null scope then "" else " trusting " <> renderRuleScope scope

renderQueryItem :: QueryItem' 'Repr 'Representation -> Text
renderQueryItem QueryItem{..} =
  intercalate ",\n" (fold
    [ renderPredicate <$> qBody
    , renderExpression <$> qExpressions
    ])
  <> if null qScope then "" else " trusting " <> renderRuleScope qScope

renderBlock :: Block -> Text
renderBlock Block{..} =
  let renderScopeLine = ("trusting " <>) . renderRuleScope
  in foldMap (<> ";\n") $ fold
        [ [renderScopeLine bScope | not (null bScope)]
        , renderRule <$> bRules
        , renderFact <$> bFacts
        , renderCheck <$> bChecks
        ]
