{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedLists            #-}
{-# LANGUAGE OverloadedStrings          #-}
{-|
  Module     : Auth.Bisque.Symbols
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
-}
module Auth.Bisque.Symbols ( BlockSymbols
                           , ReverseSymbols
                           , SymbolRef (..)
                           , Symbols
                           , addFromBlock
                           , addFromBlocks
                           , addSymbols
                           , getSymbol
                           , getSymbolCode
                           , getSymbolList
                           , newSymbolTable
                           , reverseSymbols
                           ) where

import Control.Monad      (join)
import Data.Int           (Int64)
import Data.Map           (Map, elems, (!?))
import qualified Data.Map as Map
import Data.Set           (Set, difference, union)
import qualified Data.Set as Set
import Data.Text          (Text)
import Auth.Bisque.Utils  (maybeToRight)

newtype SymbolRef = SymbolRef { getSymbolRef :: Int64 }
  deriving stock (Eq)

instance Show SymbolRef where
  show = ("#" <>) . show . getSymbolRef

newtype Symbols = Symbols { getSymbols :: Map Int64 Text }
  deriving stock (Eq, Show)

newtype BlockSymbols = BlockSymbols { getBlockSymbols :: Map Int64 Text }
  deriving stock (Eq, Show)
  deriving newtype (Semigroup)

newtype ReverseSymbols = ReverseSymbols { getReverseSymbols :: Map Text Int64 }
  deriving stock (Eq, Show)
  deriving newtype (Semigroup)

getSymbol :: Symbols -> SymbolRef -> Either String Text
getSymbol (Symbols m) (SymbolRef i) =
  maybeToRight ("Missing symbol at id #" <> show i) $ m !? i

addSymbols :: Symbols -> Set Text -> BlockSymbols
addSymbols (Symbols m) symbols =
  let existingSymbols = Set.fromList (elems commonSymbols) `union` Set.fromList (elems m)
      newSymbols = Set.toList $ symbols `difference` existingSymbols
      starting = fromIntegral $ 1024 + (Map.size m - Map.size commonSymbols)
   in BlockSymbols $ Map.fromList (zip [starting..] newSymbols)

getSymbolList :: BlockSymbols -> [Text]
getSymbolList (BlockSymbols m) = Map.elems m

newSymbolTable :: Symbols
newSymbolTable = Symbols commonSymbols

addFromBlock :: Symbols -> BlockSymbols -> Symbols
addFromBlock (Symbols m) (BlockSymbols bm) =
   Symbols $ m <> bm

addFromBlocks :: [[Text]] -> Symbols
addFromBlocks blocksTables =
  let allSymbols = join blocksTables
   in Symbols $ commonSymbols <> Map.fromList (zip [1024..] allSymbols)

reverseSymbols :: Symbols -> ReverseSymbols
reverseSymbols =
  let swap (a,b) = (b,a)
   in ReverseSymbols . Map.fromList . fmap swap . Map.toList . getSymbols

getSymbolCode :: ReverseSymbols -> Text -> SymbolRef
getSymbolCode (ReverseSymbols rm) t = SymbolRef $ rm Map.! t

commonSymbols :: Map Int64 Text
commonSymbols = Map.fromList $ zip [0..]
  [ "read"
  , "write"
  , "resource"
  , "operation"
  , "right"
  , "time"
  , "role"
  , "owner"
  , "tenant"
  , "namespace"
  , "user"
  , "team"
  , "service"
  , "admin"
  , "email"
  , "group"
  , "member"
  , "ip_address"
  , "client"
  , "client_ip"
  , "domain"
  , "path"
  , "version"
  , "cluster"
  , "node"
  , "hostname"
  , "nonce"
  , "query"
  ]
