{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Platform.HTTP
  (
    start
  ) where

import Data.Aeson (object, (.=), FromJSON, ToJSON)
import Data.Text
import Data.UUID
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
    userName :: String,
    userAddress :: String
  } deriving (Show, Generic, Eq)

instance ToJSON User
instance FromJSON User

user1 :: User
user1 = User (newUUID !! 0) "some #1 userName" "some #1 userAddress"
user2 :: User
user2 = User (newUUID !! 1) "some #2 userName" "some #2 userAddress"
user3 :: User
user3 = User (newUUID !! 2) "some #3 userName" "some #3 userAddress"

allUsers :: [User]
allUsers = [user1, user2, user3]

start :: Int -> IO ()
start port = do
  print ("Starting Server at port " ++ show port)
  scotty port $ do
    get "/" $ html $ "<h1>Backend API server (haskell Scotty)</h1>"
    get "/manoa.json" $ json allUsers
    get "/florida.json" $ do
      json $ object ["top news" .= ("Hurricane Milton weakens as it marches across central Florida" :: Text), "sports" .= ("Why 49ers should watch former UH linebacker Jeff Ulbrich, Jets interim coach" :: Text)]
    get "/pahoa.json" $ do
      json $ object ["local" .= ("A combination bus hub and library project planned for Pahoa is on track to begin construction next year." :: Text), "today" .= ("Honolulu airport’s satisfaction score this year was 593 out of a possible 1,000" :: Text)]
