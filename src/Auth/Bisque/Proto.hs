{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveAnyClass        #-}
{-# LANGUAGE DeriveGeneric         #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-|
  Module     : Auth.Bisque.Proto
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
  Haskell data structures mapping the bisque protobuf definitions
-}
module Auth.Bisque.Proto ( Algorithm (..)
                         , BinaryKind (..)
                         , Bisque (..)
                         , Block (..)
                         , CheckV2 (..)
                         , ExpressionV2 (..)
                         , FactV2 (..)
                         , Op (..)
                         , OpBinary (..)
                         , OpTernary (..)
                         , OpUnary (..)
                         , PredicateV2 (..)
                         , Proof (..)
                         , PublicKey (..)
                         , RuleV2 (..)
                         , SignedBlock (..)
                         , TermSet (..)
                         , TermV2 (..)
                         , TernaryKind (..)
                         , UnaryKind (..)
                         , decodeBlock
                         , decodeBlockList
                         , encodeBlock
                         , encodeBlockList
                         , getField
                         , putField
                         ) where

import Data.ByteString      (ByteString)
import Data.Int
import Data.ProtocolBuffers
import Data.Serialize
import Data.Text
import GHC.Generics         (Generic)

data Bisque = Bisque
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

data SignedBlock = SignedBlock
  { block     :: Required 1 (Value ByteString)
  , nextKey   :: Required 2 (Message PublicKey)
  , signature :: Required 3 (Value ByteString)
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
  } deriving (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype FactV2 = FactV2
  { predicate :: Required 1 (Message PredicateV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data RuleV2 = RuleV2
  { head        :: Required 1 (Message PredicateV2)
  , body        :: Repeated 2 (Message PredicateV2)
  , expressions :: Repeated 3 (Message ExpressionV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype CheckV2 = CheckV2
  { queries :: Repeated 1 (Message RuleV2)
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

newtype TermSet = TermSet
  { set :: Repeated 1 (Message TermV2)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

type CV2Id = Required 1 (Value Int32)
data ConstraintV2 =
    CV2Int    CV2Id (Required 2 (Message IntConstraintV2))
  | CV2String CV2Id (Required 3 (Message StringConstraintV2))
  | CV2Date   CV2Id (Required 4 (Message DateConstraintV2))
  | CV2Symbol CV2Id (Required 5 (Message SymbolConstraintV2))
  | CV2Bytes  CV2Id (Required 6 (Message BytesConstraintV2))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data IntConstraintV2 =
    ICV2LessThan       (Required 1 (Value Int64))
  | ICV2GreaterThan    (Required 2 (Value Int64))
  | ICV2LessOrEqual    (Required 3 (Value Int64))
  | ICV2GreaterOrEqual (Required 4 (Value Int64))
  | ICV2Equal          (Required 5 (Value Int64))
  | ICV2InSet          (Required 6 (Message IntSet))
  | ICV2NotInSet       (Required 7 (Message IntSet))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype IntSet = IntSet
  { set :: Packed 7 (Value Int64)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data StringConstraintV2 =
    SCV2Prefix   (Required 1 (Value Text))
  | SCV2Suffix   (Required 2 (Value Text))
  | SCV2Equal    (Required 3 (Value Text))
  | SCV2InSet    (Required 4 (Message StringSet))
  | SCV2NotInSet (Required 5 (Message StringSet))
  | SCV2Regex    (Required 6 (Value Text))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype StringSet = StringSet
  { set :: Repeated 1 (Value Text)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data DateConstraintV2 =
    DCV2Before (Required 1 (Value Int64))
  | DCV2After  (Required 2 (Value Int64))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data SymbolConstraintV2 =
    SyCV2InSet    (Required 1 (Message SymbolSet))
  | SyCV2NotInSet (Required 2 (Message SymbolSet))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype SymbolSet = SymbolSet
  { set :: Packed 1 (Value Int64)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data BytesConstraintV2 =
    BCV2Equal    (Required 1 (Value ByteString))
  | BCV2InSet    (Required 2 (Message BytesSet))
  | BCV2NotInSet (Required 3 (Message BytesSet))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype BytesSet = BytesSet
  { set :: Repeated 1 (Value ByteString)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

newtype ExpressionV2 = ExpressionV2
  { ops :: Repeated 1 (Message Op)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data Op =
    OpVValue  (Required 1 (Message TermV2))
  | OpVUnary  (Required 2 (Message OpUnary))
  | OpVBinary (Required 3 (Message OpBinary))
    deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data UnaryKind = Negate | Parens | Length
  deriving stock (Show, Enum, Bounded)

newtype OpUnary = OpUnary
  { kind :: Required 1 (Enumeration UnaryKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

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
  deriving stock (Show, Enum, Bounded)

newtype OpBinary = OpBinary
  { kind :: Required 1 (Enumeration BinaryKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

data TernaryKind =
    VerifyEd25519Signature
  deriving stock (Show, Enum, Bounded)

newtype OpTernary = OpTernary
  { kind :: Required 1 (Enumeration TernaryKind)
  } deriving stock (Generic, Show)
    deriving anyclass (Decode, Encode)

decodeBlockList :: ByteString -> Either String Bisque
decodeBlockList = runGet decodeMessage

decodeBlock :: ByteString
            -> Either String Block
decodeBlock = runGet decodeMessage

encodeBlockList :: Bisque -> ByteString
encodeBlockList = runPut . encodeMessage

encodeBlock :: Block -> ByteString
encodeBlock = runPut . encodeMessage
