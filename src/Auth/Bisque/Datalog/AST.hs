{-# LANGUAGE ApplicativeDo              #-}
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
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE StandaloneDeriving         #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE TypeFamilies               #-}
{-# LANGUAGE UndecidableInstances       #-}
module Auth.Bisque.Datalog.AST ( Binary (..)
                               , Block
                               , Block' (..)
                               , BlockIdType
                               , Check
                               , Check' (..)
                               , CheckKind (..)
                               , DatalogContext (..)
                               , Expression
                               , Expression' (..)
                               , IsWithinSet (..)
                               , PkOrSlice (..)
                               , Predicate
                               , Predicate' (..)
                               , PredicateOrFact (..)
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
                               , Unary (..)
                               , VariableType
                               , renderBlock
                               , renderFact
                               , renderRule
                               ) where

import           Data.ByteString            (ByteString)
import           Data.Foldable              (fold)
import           Data.Int                   (Int64)
-- import           Data.List.NonEmpty         (NonEmpty)
-- import           Data.Map.Strict            (Map)
-- import qualified Data.Map.Strict            as Map
import           Data.Set                   (Set)
import qualified Data.Set                   as Set
import           Data.String                (IsString)
import           Data.Text                  (Text, intercalate, pack, unpack)
import           Data.Time                  (UTCTime, defaultTimeLocale, formatTime)
import           Data.Void                  (Void, absurd)
import           Instances.TH.Lift          ()
import           Language.Haskell.TH
import           Language.Haskell.TH.Syntax
import           Numeric.Natural            (Natural)
-- import           Validation                 (Validation (..), failure)
import           Auth.Bisque.Crypto         (MyPublicKey, pkBytes)
import           Auth.Bisque.Utils         (encodeHex)

data IsWithinSet = NotWithinSet | WithinSet
data PredicateOrFact = InPredicate | InFact
data DatalogContext = WithSlices | Representation
data EvaluationContext = Repr | Eval
data PkOrSlice = PkSlice Text | Pk MyPublicKey deriving (Eq, Show)

instance Lift PkOrSlice
  where
    -- lift (PkSlice name) = [| $(varE $ mkName $ unpack name) |]
    -- lift (Pk pk)        = [| pk |]
#if MIN_VERSION_template_haskell(2,17,0)
    liftTyped = liftCode . unsafeTExpCoerce . lift
#else
    liftTyped = unsafeTExpCoerce . lift
#endif

newtype Slice = Slice Text deriving newtype (Eq, Show, Ord, IsString)

instance Lift Slice
  where
    lift (Slice name) = [| toTerm $(varE $ mkName $ unpack name) |]
#if MIN_VERSION_template_haskell(2,17,0)
    liftTyped = liftCode . unsafeTExpCoerce . lift
#else
    liftTyped = unsafeTExpCoerce . lift
#endif

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
    BlockIdType 'Repr 'Representation = MyPublicKey
    BlockIdType 'Eval 'Representation = (Set Natural, MyPublicKey)

type Term = Term' 'NotWithinSet 'InPredicate 'Representation
type Predicate = Predicate' 'InPredicate 'Representation
type Expression = Expression' 'Representation
type RuleScope = RuleScope' 'Repr 'Representation
type Rule = Rule' 'Repr 'Representation
type Query = Query' 'Repr 'Representation

type Query' evalCtx ctx = [QueryItem' evalCtx ctx]

type Check = Check' 'Repr 'Representation
type Block = Block' 'Repr 'Representation

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

data Unary =
    Negate
  | Parens
  | Length
  deriving (Eq, Ord, Show, Lift)

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

deriving instance Eq   (Term' 'NotWithinSet 'InPredicate ctx) => Eq (Expression' ctx)
deriving instance Ord  (Term' 'NotWithinSet 'InPredicate ctx) => Ord (Expression' ctx)
deriving instance Lift (Term' 'NotWithinSet 'InPredicate ctx) => Lift (Expression' ctx)
deriving instance Show (Term' 'NotWithinSet 'InPredicate ctx) => Show (Expression' ctx)

data RuleScope' (evalCtx :: EvaluationContext) (ctx :: DatalogContext) =
    OnlyAuthority
  | Previous
  | BlockId (BlockIdType evalCtx ctx)

deriving instance Eq (BlockIdType evalCtx ctx) => Eq (RuleScope' evalCtx ctx)
deriving instance Ord (BlockIdType evalCtx ctx) => Ord (RuleScope' evalCtx ctx)
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

data QueryItem' evalCtx ctx = QueryItem
  { qBody        :: [Predicate' 'InPredicate ctx]
  , qExpressions :: [Expression' ctx]
  , qScope       :: Set (RuleScope' evalCtx ctx)
  }

data CheckKind = One | All deriving (Eq, Show, Ord, Lift)

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

instance Show Block
  where
    show = unpack . renderBlock

renderBlock :: Block -> Text
renderBlock Block{..} =
  let renderScopeLine = ("trusting " <>) . renderRuleScope
  in foldMap (<> ";\n") $ fold
        [ [renderScopeLine bScope | not (null bScope)]
        , renderRule <$> bRules
        , renderFact <$> bFacts
        , renderCheck <$> bChecks
        ]

-- renderRuleScope
renderRuleScope :: Set RuleScope -> Text
renderRuleScope =
  let renderScopeElem = \case
        OnlyAuthority -> "authority"
        Previous      -> "previous"
        BlockId bs    -> "ed25519/" <> encodeHex (pkBytes bs)
  in intercalate ", " . Set.toList . Set.map renderScopeElem

-- renderRule
renderRule :: Rule -> Text
renderRule Rule{rhead,body,expressions,scope} =
    renderPredicate rhead <> " <- "
  <> intercalate ", " (fmap renderPredicate body <> fmap renderExpression expressions)
  <> if null scope then ""
                   else " trusting " <> renderRuleScope scope

renderPredicate :: Predicate -> Text
renderPredicate Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderId terms) <> ")"

renderId :: Term -> Text
renderId = renderId' ("$" <>) (renderSet absurd) absurd

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

type Fact = Predicate' 'InFact 'Representation

renderSet :: (SliceType ctx -> Text) -> Set (Term' 'WithinSet 'InFact ctx) -> Text
renderSet slice terms =
  "[" <> intercalate "," (renderId' absurd absurd slice <$> Set.toList terms) <> "]"

-- renderFact
renderFact :: Fact -> Text
renderFact Predicate{name,terms} =
  name <> "(" <> intercalate ", " (fmap renderFactId terms) <> ")"

renderFactId :: Term' 'NotWithinSet 'InFact 'Representation -> Text
renderFactId = renderId' absurd (renderSet absurd) absurd

-- renderCheck
renderCheck :: Check -> Text
renderCheck Check{..} =
  let kindToken = case cKind of
        One -> "if"
        All -> "all"
  in "check " <> kindToken <> " " <>
    intercalate "\n or " (renderQueryItem <$> cQueries)

renderQueryItem :: QueryItem' 'Repr 'Representation -> Text
renderQueryItem QueryItem{..} =
  intercalate ",\n" (fold
    [ renderPredicate <$> qBody
    , renderExpression <$> qExpressions
    ])
  <> if null qScope then ""
                    else " trusting " <> renderRuleScope qScope

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
