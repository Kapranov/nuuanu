{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
-- |
--  Module     : Auth.Kailua.Types
--  Copyright  : updated © Oleg G.Kapranov, 2025
--  License    : MIT
--  Maintainer : lugatex@yahoo.com
module Auth.Kailua.Types ( Algorithm (..)
                         , BinaryKind (..)
                         , Block (..)
                         , CheckKind (..)
                         , CheckV2 (..)
                         , ExpressionV2 (..)
                         , ExternalSig (..)
                         , FactV2 (..)
                         , Kailua (..)
                         , Op (..)
                         , OpBinary (..)
                         , OpTernary (..)
                         , OpUnary (..)
                         , PredicateV2 (..)
                         , Proof (..)
                         , PublicKey (..)
                         , PublicKeyRef (..)
                         , RuleV2 (..)
                         , Scope (..)
                         , ScopeType (..)
                         , SignedBlock (..)
                         , SymbolRef (..)
                         , TermSet (..)
                         , TermV2 (..)
                         , TernaryKind (..)
                         , ThirdPartyBlockContents (..)
                         , ThirdPartyBlockRequest (..)
                         , UnaryKind (..)
                         ) where

import Data.ByteString      (ByteString)
import Data.Int
import Data.Map             (Map, elems, (!?))
import qualified Data.Map   as Map
import Data.ProtocolBuffers
import Data.Text
import GHC.Generics         (Generic)

data Kailua = Kailua
  { rootKeyId :: Optional 1 (Value Int32)
  , authority :: Required 2 (Message SignedBlock)
  , blocks    :: Repeated 3 (Message SignedBlock)
  , proof     :: Required 4 (Message Proof)
  } deriving (Generic, Show)
    deriving anyclass (Decode, Encode)

data Proof =
    ProofSecret    (Required 1 (Value ByteString))
  | ProofSignature (Required 2 (Value ByteString))
  deriving (Generic, Show)
  deriving anyclass (Decode, Encode)

data ExternalSig = ExternalSig
  { signature :: Required 1 (Value ByteString)
  , publicKey :: Required 2 (Message PublicKey)
  }
  deriving (Generic, Show)
  deriving anyclass (Decode, Encode)

data SignedBlock = SignedBlock
  { block       :: Required 1 (Value ByteString)
  , nextKey     :: Required 2 (Message PublicKey)
  , signature   :: Required 3 (Value ByteString)
  , externalSig :: Optional 4 (Message ExternalSig)
  }
  deriving (Generic, Show)
  deriving anyclass (Decode, Encode)

data Algorithm = Ed25519
  deriving stock (Show, Enum, Bounded)

data PublicKey = PublicKey
  { algorithm :: Required 1 (Enumeration Algorithm)
  , key       :: Required 2 (Value ByteString)
  }
  deriving (Generic, Show)
  deriving anyclass (Decode, Encode)

data Block = Block {
    symbols   :: Repeated 1 (Value Text)
  , context   :: Optional 2 (Value Text)
  , version   :: Optional 3 (Value Int32)
  , facts_v2  :: Repeated 4 (Message FactV2)
  , rules_v2  :: Repeated 5 (Message RuleV2)
  , checks_v2 :: Repeated 6 (Message CheckV2)
  , scope     :: Repeated 7 (Message Scope)
  , pksTable  :: Repeated 8 (Message PublicKey)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data ScopeType =
    ScopeAuthority
  | ScopePrevious
  deriving stock (Show, Enum, Bounded)

data Scope =
    ScType  (Required 1 (Enumeration ScopeType))
  | ScBlock (Required 2 (Value Int64))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data RuleV2 = RuleV2
  { head        :: Required 1 (Message PredicateV2)
  , body        :: Repeated 2 (Message PredicateV2)
  , expressions :: Repeated 3 (Message ExpressionV2)
  , scope       :: Repeated 4 (Message Scope)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data CheckKind =
    One
  | All
  deriving stock (Show, Enum, Bounded)

data CheckV2 = CheckV2
  { queries :: Repeated 1 (Message RuleV2)
  , kind    :: Optional 2 (Enumeration CheckKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data PredicateV2 = PredicateV2
  { name  :: Required 1 (Value Int64)
  , terms :: Repeated 2 (Message TermV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data TermV2 =
    TermVariable (Required 1 (Value Int64))
  | TermInteger  (Required 2 (Value Int64))
  | TermString   (Required 3 (Value Int64))
  | TermDate     (Required 4 (Value Int64))
  | TermBytes    (Required 5 (Value ByteString))
  | TermBool     (Required 6 (Value Bool))
  | TermTermSet  (Required 7 (Message TermSet))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data Op =
    OpVValue  (Required 1 (Message TermV2))
  | OpVUnary  (Required 2 (Message OpUnary))
  | OpVBinary (Required 3 (Message OpBinary))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data UnaryKind = Negate | Parens | Length
  deriving stock (Show, Enum, Bounded)

data BinaryKind =
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
  deriving stock (Show, Enum, Bounded)

data TernaryKind =
    VerifyEd25519Signature
  deriving stock (Show, Enum, Bounded)

data ThirdPartyBlockRequest
  = ThirdPartyBlockRequest
  { previousPk :: Required 1 (Message PublicKey)
  , pkTable    :: Repeated 2 (Message PublicKey)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data ThirdPartyBlockContents
  = ThirdPartyBlockContents
  { payload     :: Required 1 (Value ByteString)
  , externalSig :: Required 2 (Message ExternalSig)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype FactV2 = FactV2
  { predicate :: Required 1 (Message PredicateV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype TermSet = TermSet
  { set :: Repeated 1 (Message TermV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype ExpressionV2 = ExpressionV2
  { ops :: Repeated 1 (Message Op)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype OpUnary = OpUnary
  { kind :: Required 1 (Enumeration UnaryKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype OpBinary = OpBinary
  { kind :: Required 1 (Enumeration BinaryKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype OpTernary = OpTernary
  { kind :: Required 1 (Enumeration TernaryKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype SymbolRef = SymbolRef { getSymbolRef :: Int64 }
  deriving stock (Eq, Ord)
  deriving newtype (Enum)

newtype PublicKeyRef = PublicKeyRef { getPublicKeyRef :: Int64 }
  deriving stock (Eq, Ord)
  deriving newtype (Enum)

instance Show SymbolRef where
  show = ("#" <>) . show . getSymbolRef

instance Show PublicKeyRef where
  show = ("#" <>) . show . getPublicKeyRef
