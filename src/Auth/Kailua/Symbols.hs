{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE NamedFieldPuns             #-}
{-# LANGUAGE OverloadedLists            #-}
{-# LANGUAGE OverloadedStrings          #-}
{-|
  Module     : Auth.Kailua.Symbols
  Copyright  : updated © Oleg G.Kapranov, 2025
  License    : MIT
  Maintainer : lugatex@yahoo.com
-}
module Auth.Kailua.Symbols ( BlockSymbols
                           , PublicKeyRef (..)
                           , ReverseSymbols
                           , SymbolRef (..)
                           , Symbols
                           , addFromBlock
                           , addSymbols
                           , getPkList
                           , getPkTable
                           , getPublicKey'
                           , getPublicKeyCode
                           , getSymbol
                           , getSymbolCode
                           , getSymbolList
                           , newSymbolTable
                           , registerNewPublicKeys
                           , registerNewSymbols
                           , reverseSymbols
                           ) where

import           Auth.Kailua.Crypto (PublicKey)
import           Auth.Kailua.Types  ( PublicKeyRef (..)
                                    , SymbolRef (..)
                                    )
import           Auth.Kailua.Utils  (maybeToRight)
import           Data.Int           (Int64)
import           Data.List          ((\\))
import           Data.Map           ( Map
                                    , elems
                                    , (!?)
                                    )
import qualified Data.Map           as Map
import           Data.Set           ( Set
                                    , difference
                                    , union
                                    )
import qualified Data.Set           as Set
import           Data.Text          (Text)

data Symbols = Symbols
  { symbols    :: Map SymbolRef Text
  , publicKeys :: Map PublicKeyRef PublicKey
  } deriving stock (Eq, Show)

data BlockSymbols = BlockSymbols
  { blockSymbols    :: Map SymbolRef Text
  , blockPublicKeys :: Map PublicKeyRef PublicKey
  } deriving stock (Eq, Show)

data ReverseSymbols = ReverseSymbols
  { reverseSymbolMap    :: Map Text SymbolRef
  , reversePublicKeyMap :: Map PublicKey PublicKeyRef
  }
  deriving stock (Eq, Show)

instance Semigroup BlockSymbols where
  b <> b' = BlockSymbols
              { blockSymbols = blockSymbols b <> blockSymbols b'
              , blockPublicKeys = blockPublicKeys b <> blockPublicKeys b'
              }

instance Semigroup ReverseSymbols where
  b <> b' = ReverseSymbols
              { reverseSymbolMap = reverseSymbolMap b <> reverseSymbolMap b'
              , reversePublicKeyMap = reversePublicKeyMap b <> reversePublicKeyMap b'
              }

commonSymbols :: Map SymbolRef Text
commonSymbols = Map.fromList $ zip [SymbolRef 0..]
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

getNextOffset :: Symbols -> SymbolRef
getNextOffset (Symbols m _) =
  SymbolRef $ fromIntegral $ 1024 + (Map.size m - Map.size commonSymbols)

getNextPublicKeyOffset :: Symbols -> PublicKeyRef
getNextPublicKeyOffset (Symbols _ m) =
  PublicKeyRef $ fromIntegral $ Map.size m

addSymbols :: Symbols -> Set Text -> Set PublicKey -> BlockSymbols
addSymbols s@(Symbols sm pkm) bSymbols pks =
  let existingSymbols = Set.fromList (elems commonSymbols) `union` Set.fromList (elems sm)
      newSymbols = Set.toList $ bSymbols `difference` existingSymbols
      starting = getNextOffset s
      existingPks = Set.fromList (elems pkm)
      newPks = Set.toList $ pks `difference` existingPks
      startingPk = getNextPublicKeyOffset s
  in BlockSymbols
       { blockSymbols = Map.fromList (zip [starting..] newSymbols)
       , blockPublicKeys = Map.fromList (zip [startingPk..] newPks)
       }

getSymbol :: Symbols -> SymbolRef -> Either String Text
getSymbol (Symbols m _) i =
  maybeToRight ("Missing symbol at id " <> show i) $ m !? i

getPublicKey' :: Symbols -> PublicKeyRef -> Either String PublicKey
getPublicKey' (Symbols _ m) i =
  maybeToRight ("Missing symbol at id " <> show i) $ m !? i

getSymbolList :: BlockSymbols -> [Text]
getSymbolList (BlockSymbols m _) = Map.elems m

getPkList :: BlockSymbols -> [PublicKey]
getPkList (BlockSymbols _ m) = Map.elems m

getPkTable :: Symbols -> [PublicKey]
getPkTable (Symbols _ m) = Map.elems m

newSymbolTable :: Symbols
newSymbolTable = Symbols commonSymbols Map.empty

addFromBlock :: Symbols -> BlockSymbols -> Symbols
addFromBlock (Symbols sm pkm) (BlockSymbols bsm bpkm) =
   Symbols
     { symbols = sm <> bsm
     , publicKeys = pkm <> bpkm
     }

registerNewSymbols :: [Text] -> Symbols -> Symbols
registerNewSymbols newSymbols s@Symbols{symbols} =
  let newSymbolsMap = Map.fromList $ zip [getNextOffset s..] newSymbols
  in s { symbols = symbols <> newSymbolsMap }

registerNewPublicKeys :: [PublicKey] -> Symbols -> Symbols
registerNewPublicKeys newPks s@Symbols{publicKeys} =
  let newPkMap = Map.fromList $ zip [getNextPublicKeyOffset s..] (newPks \\ elems publicKeys)
  in s { publicKeys = publicKeys <> newPkMap }

reverseSymbols :: Symbols -> ReverseSymbols
reverseSymbols (Symbols sm pkm) =
  let swap (a,b) = (b,a)
      reverseMap :: (Ord b) => Map a b -> Map b a
      reverseMap = Map.fromList . fmap swap . Map.toList
  in ReverseSymbols
      { reverseSymbolMap = reverseMap sm
      , reversePublicKeyMap = reverseMap pkm
      }

getSymbolCode :: ReverseSymbols -> Text -> SymbolRef
getSymbolCode (ReverseSymbols rm _) t = rm Map.! t

getPublicKeyCode :: ReverseSymbols -> PublicKey -> Int64
getPublicKeyCode (ReverseSymbols _ rm) t = getPublicKeyRef $ rm Map.! t
