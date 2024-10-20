{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}

module Platform.HTTP
  (
    start
  ) where

import Data.Aeson (object, (.=), FromJSON, ToJSON)
import Data.Text
import Data.UUID
import Faker
import Faker.Address
import Faker.Combinators
import Faker.Name
import GHC.List as L
import GHC.Generics
import System.Random
import Web.Scotty


newUUID :: [UUID]
newUUID =
  let seed = 123
      g0 = mkStdGen seed
      (u1, g1) = random g0
      (u2, g2) = random g1
      (u3, _g3) = random g2
   in [u1,u2,u3]

data User =
  User {
    userId :: UUID,
    userName :: Text,
    userAddress :: Text
  } deriving (Show, Generic, Eq)

instance ToJSON User
instance FromJSON User

matchesId :: String -> User -> Bool
matchesId beam user = toString (userId user) == beam

start :: Int -> IO ()
start port = do
  dataName <- generateNonDeterministic $ listOf 3 name
  dataAddress <- generateNonDeterministic $ listOf 3  fullAddress
  let user1 = User (newUUID !! 0) (dataName !! 0) (dataAddress !! 0)
  let user2 = User (newUUID !! 1) (dataName !! 1) (dataAddress !! 1)
  let user3 = User (newUUID !! 2) (dataName !! 2) (dataAddress !! 2)
  let allUsers = [user1,user2, user3]
  print ("Starting Server at port " ++ show port)
  scotty port $ do
    get "/" $ html $ "<h1>Backend API server (haskell Scotty)</h1>"
    get "/users/:word" $ do { beam <- captureParam "word" ; json (L.filter (matchesId beam) allUsers) }
    get "/manoa.json" $ json allUsers
    get "/florida.json" $ do
      json $ object ["top news" .= ("Hurricane Milton weakens as it marches across central Florida" :: Text), "sports" .= ("Why 49ers should watch former UH linebacker Jeff Ulbrich, Jets interim coach" :: Text)]
    get "/pahoa.json" $ do
      json $ object ["local" .= ("A combination bus hub and library project planned for Pahoa is on track to begin construction next year." :: Text), "today" .= ("Honolulu airport’s satisfaction score this year was 593 out of a possible 1,000" :: Text)]
