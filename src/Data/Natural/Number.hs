{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module Data.Natural.Number (main) where

import Data.Kind

data Nat = Zero | Succ Nat deriving (Eq, Show)

data Vector (n :: Nat) (a :: Type) where
  VNil :: Vector Zero a
  VCons :: a -> Vector n a -> Vector (Succ n) a

instance Show a => Show (Vector n a) where
  show VNil = "VNil"
  show (VCons a as) = "VCons " ++ show a ++ " (" ++ show as ++ ")"

-- add :: Nat -> Nat -> Nat
-- add Zero x = x
-- add (Succ n) y = add n (Succ y)

type family Add (n :: Nat) (m :: Nat) :: Nat
  where
    Add Zero n = n
    Add (Succ n) m = Add n (Succ m)

main :: IO ()
main = putStrLn "Aloha!"
