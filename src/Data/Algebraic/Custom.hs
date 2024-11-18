{-# LANGUAGE
    DataKinds
  , ExplicitForAll
  , FlexibleInstances
  , GADTs
  , KindSignatures
  , OverloadedStrings
#-}

module Data.Algebraic.Custom (main) where

-- import Data.List
import Data.Text (Text)
import Data.String( IsString(..) )
-- import Data.Kind

-- Making custom data types in Haskell
--    [1]      [2]        [3]
data Point = Point2D Double Double deriving (Show, Eq)
-- [1]: Type constructor
-- [2]: Data constructor
-- [3]: Types wrapped

-- | Create new values of this type via the data constructor:
--
-- >>> a = Point2D 3 4
--
-- | Show types:
-- >>> :t a
-- a :: Point
--
-- | Return values:
--
-- >>> a
-- Point2D 3.0 4.0
--
-- | Create functions that pattern match on constructors and values:
--
-- >>> b = Point2D 1 2
--
-- >>> distance (Point2D x1 y1) (Point2D x2 y2) = sqrt ((x1 - x2) ^ 2 + (y1 - y2) ^ 2)
--
-- >>> distance a b
-- 2.8284271247461903
--

-- Polymorphic data types
data PPoint a = PPoint2D a a deriving (Show, Eq)

-- Our previously created Point2D data type can contain only
-- double-precision floats. In some cases, we would want it
-- to work with other numbers as well.
-- If so, we need to make it polymorphic (able to work with
-- multiple different data types).
--
-- |  `Point` and `PPoint` are a concrete type:
-- >>> :k Point
-- Point :: *
-- >>> :k PPoint
-- PPoint :: * -> *
--
-- Another typical example of a polymorphic product type is
-- the tuple type.
-- >>> :i (,)
-- type (,) :: * -> * -> *
-- data (,) a b = (,) a b
-- ...

-- Records
-- The individual types of our `Point` and `PPoint` type are not named.
-- While it doesn’t really add any difficulty right now, working with
-- something like `Person String String String String` can be confusing.
--
-- An alternative is to use records, which have field labels.
--
data PPPoint = PPPoint2D
  { x :: Double
  , y :: Double
  }
  deriving (Show, Eq)

-- >>> a = PPPoint2D 3 4
-- >>> a
-- PPPoint2D {x = 3.0, y = 4.0}
--
-- Records also provide us with getter functions for free. The names
-- of those getters are the same as the field names.
--
-- >>> x a
-- 3.0
-- >>> y a
-- 4.0
--
-- You can update a record by providing the fields you want to update
-- rest will stay the same.
--
-- >>> b = a {x = 4}
-- >>> b
-- PPPoint2D {x = 4.0, y = 4.0}
--
-- And you can put these two things together to create functional
-- record updates.
--
-- >>> moveUp point = point {y = y point + 1}
-- >>> c = moveUp a
-- >>> c
-- PPPoint2D {x = 3.0, y = 5.0}
--
-- Of course, you can also work with records via pattern matching as
-- with basic product types.
--
-- >>> getX (PPPoint2D x _) = x
-- >>> getX a
-- 3.0
--
-- Definition of an algebraic data type
-- By putting together sum and product types, we can construct
-- elaborate types out of simple building blocks.
-- And this is what algebraic data types work with.
-- They are a collection of one or more data constructors,
-- composed with the `|` operator. In other words, they are a
-- sum of products.
--
-- data Point2D = Point2DD Double Double
-- data Point3D = Point3DD Double Double Double
--                      [1]            [2]             [3]
-- data PointD = Point2DD Double Double | Point3DD Double Double Double
-- The Point data type is a sum ([2]) of products ([1], [3])

-- Common ADTs
-- Let’s look at two commonly used ADTs in Haskell: `Maybe` and `Either`
-- safeHeadM :: [a] -> Maybe a
-- safeHeadM [] = Nothing
-- safeHeadM (n:_) = Just n
--
-- safeHeadM :: [a] -> Maybe a
-- safeHeadM ns = case ns of
--   (n:_) -> Just n
--   [] -> Nothing

-- safeHeadE :: [a] -> Either String a
-- safeHeadE [] = Left "I have no head."
-- safeHeadE (m:_) = Right m
--
-- safeHeadE :: [a] -> Either String a
-- safeHeadE ms = case ms of
--   (m:_) -> Right m
--   [] -> Left "I have no head."

-- Exponential types (functions)
data Light = Green | Yellow | Red  deriving (Show, Eq)

-- Just like values/terms can be classified into types,
-- types can be classified into kinds.
-- data Person = MkPerson { name :: String, age :: Int } deriving (Show)

-- firstPerson :: Person
-- firstPerson = MkPerson "Michael Smith" 32

-- incomplete :: Person -> Person
-- incomplete firstRecord = firstRecord

-- complete :: Person
-- complete = incomplete firstPerson

-- https://www.schoolofhaskell.com/user/k_bx/playing-with-datakind

-- data JobDescription = JobOne | JobTwo | JobThree deriving (Show, Eq)

-- data SJobDescription :: JobDescription -> *
--   where
--     SJobOne :: { jobOneN :: Int } -> SJobDescription JobOne
--     SJobTwo :: SJobDescription JobTwo
--     SJobThree :: { jobThreeN :: Int } -> SJobDescription JobThree

-- taskOneWorker :: SJobDescription JobOne -> IO ()
-- taskOneWorker t = do
--   putStrLn $ "Job: " ++ (show $ jobOneN t)

-- data List l = VCons l (List l) | VNil

--class Functor (f :: * -> *) where
--  fmap :: forall (a :: *) (b :: *). (a -> b) -> (f a -> f b)

-- class Functor f
--   where
--     fmap :: (a -> b) -> (f a -> f b)

-- data Nat = Zero | Succ Nat deriving (Eq, Show)

-- data Vector (n :: Nat) (a :: Type) where
--   Nil :: Vector Zero a
--   Cons :: a -> Vector n a -> Vector (Succ n) a

-- instance Show a => Show (Vector n a) where
--   show Nil = "Nil"
--   show (Cons a as) = "Cons " ++ show a ++ " (" ++ show as ++ ")"

-- add :: Nat -> Nat -> Nat
-- add Zero k = k
-- add (Succ p) v = add p (Succ v)

--type family add (n :: Nat) (m :: Nat) :: Nat
--  where
--    add Zero n = n
--    add (Succ n) m = add n (Succ m)

class Foo a
  where
    foo :: a -> String

instance Foo String
  where
    foo _ = "String"

instance Foo Text
  where
    foo _ = "Text"

-- import ModuleA (ExampleText(..), example)
newtype MyString = MyString String deriving (Eq, Show)

instance IsString MyString
  where
    fromString = MyString

greet :: MyString -> MyString
greet "hello" = "world"
greet other = other

newtype ExampleText = ExampleText Text

example :: ExampleText -> IO ()
example (ExampleText t) = print t

data PreferredContactMethod = Email String
  | TextMessage String
  | Mail String String String Int
  deriving Show

emailContact :: PreferredContactMethod
emailContact = Email "lugatex@yahoo.com"

textContact :: PreferredContactMethod
textContact = TextMessage "+380 99 717 0609"

mailContact :: PreferredContactMethod
mailContact = Mail "Monsarrat Ave" "Suite 712" "Honolulu HI" 96815

confirmContact :: PreferredContactMethod -> String
confirmContact contact =
  case contact of
    Email emailAddress ->
      "Okay, I'll email you at " <> emailAddress
    TextMessage number ->
      "Okay, I'll text you at " <> number
    Mail street1 street2 city_state zip_code ->
      "Okay I'll send a letter to\n"
      <> street1 <> "\n"
      <> street2 <> "\n"
      <> city_state <> " "
      <> show zip_code

data StringOrNumber = S String | N Int deriving Show

stringsAndNumbers :: [StringOrNumber]
stringsAndNumbers =
  [ S "This list has"
  , N 2
  , S "different types of vaues"
  ]

convertStringsAndNums :: StringOrNumber -> Maybe String
convertStringsAndNums xs = case xs of
  S someText -> Just someText
  N _ -> Nothing

data MyList t = Empty | Entry t (MyList t) deriving Show

addOne :: Int -> Int
addOne num = num + 1

addOneToList :: MyList Int -> MyList Int
addOneToList Empty = Empty
addOneToList (Entry n  list) = (Entry (n + 1) (addOneToList list))

addOnetoString :: MyList String -> MyList String
addOnetoString Empty = Empty
addOnetoString (Entry n list) = (Entry (n) (addOnetoString list))

-- Return the first element of a list, taking care of the edge-case where
-- the list may be empty. Which is why the result is a (Maybe a)
-- firstElem :: [a] -> Maybe a
-- firstElem xs = case xs of
--                 [] -> Nothing
--                 (x:_) -> Just x

-- Return the second element of a list
-- secondElem :: [a] -> Maybe a
-- secondElem xs = case xs of
--                  (_:y:_) -> Just y
--                  (_:[]) -> Nothing
--                  [] -> Nothing

-- Complex example using multiple list-related functions
-- let x = [1, 5, 20, 77, 45, 67]
-- in case x of
--     [] -> "(none)"
--     [a] -> show a
--     [a, b] -> show a ++ " and " ++ show b
--     [a, b, c] -> show a ++ ", " ++ show b ++ ", and " ++ show c
--     (a:b:c) -> show a ++ ", " ++ show b ++ ", and (" <> (show $ length c) <> ") more"

-- let x = [10, 20, 30]
--     y = 99
-- in y:x

-- Find the first element greater than 10
-- find (\x -> x > 10) [5, 8, 7, 12, 11, 10, 99]
-- find (> 10) [5, 8, 7, 12, 11, 10, 99]

-- Find the first user that has an incorrect age (you can possibly
-- use this to build some sort of validation in an API)
-- let users = [("Saurabh", 35), ("John", 45), ("Doe", -5)]
-- in case (find (\(_, age) -> age < 1 || age > 100) users) of
--   Nothing -> Right users
--   Just (name, age) -> Left $ name <> " seems to have an incorrect age: " <> show age

-- elem 5 [1, 2, 5, 10]
-- 5 `elem` [1, 2, 5, 10]
-- ("Saurabh", 35) `elem` [("Saurabh", 35), ("John", 45), ("Doe", -5)]

-- select all even elements from a list
-- filter (\x -> x `mod` 2 == 0) [1..20]

-- A more complex example that uses `filter` as well as `null`
-- let users = [("Saurabh", 35), ("John", 45), ("Trump", 105), ("Biden", 88), ("Doe", -5)]
--     incorrectAge = filter (\(_, age) -> age < 1 || age > 100) users
-- in if (null incorrectAge)
--    then Right users
--    else Left $ "Multiple users seem to have an incorrect age: " <> show incorrectAge

-- let x = [1, 5, 20, 77, 45, 67]
-- in take 3 x

-- `N` is greater than the list length
-- let x = [1, 5, 20, 77, 45, 67]
-- in take 10 x

-- keep selecting elements from a [Char] till we encounter a comma
-- takeWhile (\x -> x /= ',') ['H', 'e', 'l', 'l', 'o', ',', 'W', 'o', 'r', 'l', 'd']

-- keep selecting elements from a [Char] till we encounter a comma
-- takeWhile (\x -> x /= ',') "Hello,World"

-- keep selecting elements from a [Char] till we encounter a comma
-- takeWhile (/= ',') "Hello,World"

-- let numbers = [x * 0.9 | x <- [1..10]]
-- let evenNumbers = [x | x <- [1..10], even x]
-- let pairs = [(x, y) | x <- ["Fatima", "Kazuya"], y <- ["Dr. Newton", "Dr. Gomez"]]
-- let meals = [("Burger", 3, 310), ("Pizza", 5, 340), ("Ramen", 2, 250)]
-- let filteredMeals = [name | (name, price, calories) <- meals, price < 4, calories > 300]

-- I want to write a function which takes a input list and manipulates it in the following way:
-- Step 1: Take the first element of the list and the last element of the list and put it together in a sublist
-- Step 2: Take the second element of the list and the second last element of the list and put it together in the next sublist
-- Step 3: Take the third element of the list and the third last element of the list and put it together in next sublist
-- Continue this according to the same scheme (for a list of n elements)...
-- If the number of elements of the input list is odd the n/2 element of the input list will be added as last sublist of the output list.
-- input [1..10]
-- should be transformed to
-- [[1,7],[2,6],[3,5],[4]]
-- pairs1 :: [a] -> [[a]]
-- pairs1 [] = []
-- pairs1 (x1:x2:xs) = [x1,x2]: pairs1 xs
-- pairs1 xs = [xs]

-- pairs2 :: [a] -> [[a]]
-- pairs2 xs = fst (go xs xs) where
--   go (x:xs) (_:_:ys) = f x (go xs ys)
--   go (x:xs) [_]      = ([[x]],xs)
--   go xs     []       = ([],xs)
--   f x (xs,y:ys) = ([x,y]:xs,ys)

-- pairs3 :: [a] -> [[a]]
-- pairs3 xs = go xs xs (const []) where
--   go (y:ys) (_:_:zs) k = go ys zs (f y k)
--   go (y:ys) [_]      k = [y] : k ys
--   go ys     []       k = k ys
--   f x k (y:ys) = [x,y] : k ys

-- pairs4 xs =
--   transpose [take (x + y) xs, take x (reverse xs)]
--     where (x, y) = (length xs) `divMod` 2

-- pairs5 :: [a] -> [[a]]
-- pairs5 [] = []
-- pairs5 xs = [first xs] ++ (pairs1 . drop 1 $ init xs)
--       where first (x:[]) = [x]
--             first xs = [head xs, last xs]

-- pairs6 xs = take (length xs `div` 2) $ zip xs (reverse xs)

-- pairs7 = unfoldr (\xs ->
--   if length xs < 2
--   then Nothing
--   else Just ([head xs, last xs], init.tail $ xs))

main :: IO ()
main = do
  let data_email = confirmContact emailContact
  let data_mail = confirmContact mailContact
  let data_strings = head stringsAndNumbers
  let data_text = confirmContact textContact
  print $ convertStringsAndNums data_strings
  print data_email
  print data_mail
  print data_text
  print $ addOne 5
  print $ addOneToList $ Entry 5 Empty
  print $ addOneToList $ Entry 5 $ Entry 10 Empty
  print $ addOnetoString $ Entry "tleaves" Empty
  print $ addOnetoString $ Entry "programming" $ Entry "like it's" $ Entry "1979" Empty
  print $ foo $ ("Waipahu" :: String)
  print $ foo $ ("Sunset Beach" :: Text)
  print $ greet "Kokua Line"
  print $ greet "Kauai cliffs"
  example $ ExampleText "A string literal"
  putStrLn "Algebraic Data Types in Haskell"
