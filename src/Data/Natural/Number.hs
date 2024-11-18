{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}

module Data.Natural.Number (main) where

-- data PokerCard = PokerCard { rank :: Rank, suit :: Suit } deriving (Eq)
--
-- of :: Rank -> Suit -> PokerCard
-- r of s = PokerCard { rank = r, suit = s }
-- pokerDeck [Ace of Spades, Two of Spades]
--
-- of :: Rank -> Suit -> PokerCard
-- r `of` s = PokerCard { rank = r, suit = s }
--
-- (@@) :: Rank -> Suit -> PokerCard
-- r @@ s = PokerCard { rank = r, suit = s }
--
-- data OF = OF
-- ace :: OF -> Suit -> PokerCard
-- ace _ s = PokerCard Ace s
--
-- or point-free
-- two :: OF -> Suit -> PokerCard
-- two _ = PokerCard Two
--
-- or with const
-- three :: OF -> Suit -> PokerCard
-- three = const (PokerCard Three)
--
-- the rest in one line
-- four,five,six,seven,eight,nine,ten,jack,king :: OF -> Suit -> PokerCard
-- [four,five,six,seven,eight,nine,ten,jack,king] = map (const . PokerCard) [Four .. King]
--
-- now you can write
-- pokerDeck = [ace OF Spades, two OF Spades]
--
-- {-# LANGUAGE FlexibleInstances #-}
-- instance Num (Rank -> Suit) where
--   fromInteger n = (undefined : map Card[Ace .. King]) !! (fromInteger n)
--
-- Operators are infix, so you could define something like:
-- (#) :: Rank -> Suit -> PokerCard
-- r # s = PokerCard { rank = r, suit = s }
-- pokerDeck = [Ace ::: Spades, ...]
-- pokerDeck = [Ace `of` Spades, ...]
--
-- data Test = Test String deriving (Eq, Show)
--
-- Now let's define right- and left- associative operators:
--
-- (>:) :: Test -> Test -> Test
-- (Test a) >: (Test b) = Test $ "(" ++ a ++ " >: " ++ b ++ ")"
--
-- (<:) :: Test -> Test -> Test
-- (Test a) <: (Test b) = Test $ "(" ++ a ++ " <: " ++ b ++ ")"
-- infixr 6 >:
-- infixl 6 <:
--
-- If we test it out we see that it works correctly:
--
-- print $ (Test "1") >: (Test "2") >: (Test "4")
-- Test "(1 >: (2 >: 4))"
-- print $ (Test "1") <: (Test "2") <: (Test "4")
-- Test "((1 <: 2) <: 4)"
--
-- (?:) :: Test -> Test -> Test
-- (Test a) ?: (Test b) = Test $ "(" ++ a ++ " ?: " ++ b ++ ")"
-- infix 6 ?:
--
-- And then let's try it:
--
-- print $ (Test "1") ?: (Test "2") ?: (Test "4")
--
-- Woops, we get:
-- Precedence parsing error cannot mix `?:' [infix 6] and `?:' [infix 6] in the same infix expression
--
-- If we instead remove the last term:
--
-- print $ (Test "1") ?: (Test "2")
-- Test "(1 ?: 2)"
--
-- print $ (Test "1") ?: ((Test "2") ?: (Test "4"))
-- Test "(1 ?: (2 ?: 4))"

-- Composition operator
-- f :: Bool -> String
-- f x =
--   case x of
--     True -> "it is true"
--     False -> "it is false"

-- g :: Int -> Bool
-- g x = x == 1
-- (f.g) 5 -- it is false
-- f.g $ 1 -- it is true

-- pointfree version
-- share :: Show a => a -> IO()
-- share = putStrLn . show

-- data Tree a = EmptyTree | Node a (Tree a) (Tree a) deriving (Show, Read, Eq)

-- data TrafficLight = Red | Yellow | Green

-- instance Eq TrafficLight
--   where
--     Red == Red = True
--     Green == Green = True
--     Yellow == Yellow = True
--     _ == _ = False

-- instance Show TrafficLight
--   where
--     show Red = "Red light"
--     show Yellow = "Yellow light"
--     show Green = "Green light"

-- A yes-no typeclass
-- class YesNo a where yesno :: a -> Bool

-- instance YesNo Int
--   where
--     yesno 0 = False
--     yesno _ = True

-- instance YesNo [a]
--   where
--     yesno [] = False
--     yesno _ = True

-- instance YesNo Bool
--   where
--     yesno = id

-- instance YesNo (Maybe a)
--   where
--     yesno (Just _) = True
--     yesno Nothing = False

-- instance YesNo (Tree a)
--   where
--     yesno EmptyTree = False
--     yesno _ = True

-- instance YesNo TrafficLight
--   where
--     yesno Red = False
--     yesno _ = True

-- yesno $ length []
-- yesno "haha"
-- yesno ""
-- yesno $ Just 0
-- yesno True
-- yesno EmptyTree
-- yesno []
-- yesno [0,0,0]
-- :t yesno

-- yesnoIf :: (YesNo y) => y -> a -> a -> a
-- yesnoIf yesnoVal yesResult noResult = if yesno yesnoVal then yesResult else noResult

-- yesnoIf [] "YEAH!" "NO!"
-- yesnoIf [2,3,4] "YEAH!" "NO!"
-- yesnoIf True "YEAH!" "NO!"
-- yesnoIf (Just 500) "YEAH!" "NO!"
-- yesnoIf Nothing "YEAH!" "NO!"

-- The Functor typeclass
-- class FunctorExample f
--   where
--     fmap :: (a -> b) -> f a -> f b

-- instance FunctorExample []
--   where
--     fmap = map

-- instance FunctorExample Maybe
--   where
--     fmap f (Just x) = Just (f x)
--     fmap f Nothing = Nothing

-- Kinds and some type-foo

-- data Frank a b  = Frank {frankField :: b a} deriving (Show)

-- :t Frank {frankField = Just "HAHA"}
-- :t Frank {frankField = Node 'a' EmptyTree EmptyTree}
-- :t Frank {frankField = "YES"}

-- data Barry t k p = Barry { yabba :: p, dabba :: t k }

-- :k Barry
-- Barry :: (k -> *) -> k -> * -> *

-- class Tofu t
--   where
--     tofu :: j a -> t a j

-- instance Tofu Frank
--   where
--     tofu x = Frank x

-- tofu (Just 'a') :: Frank Char Maybe
-- Frank {frankField = Just 'a'}
-- tofu ["HELLO"] :: Frank [Char] []
-- Frank {frankField = ["HELLO"]}

-- instance FunctorExample (Barry a b)
--   where
--     fmap f (Barry {yabba = x, dabba = y}) = Barry {yabba = f x, dabba = y}

main :: IO ()
main = putStrLn "Aloha!"
