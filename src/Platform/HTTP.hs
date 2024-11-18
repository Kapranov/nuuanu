{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}

module Platform.HTTP
  (
    start
  ) where

import Control.Monad()
import Control.Monad.IO.Class
import Data.Aeson (Value (Null), object, (.=), FromJSON, ToJSON)
import Data.Text
import Data.Time (getCurrentTime, UTCTime)
import Data.Time.Format
import Data.UUID
import Faker
import Faker.Address
import Faker.Combinators
import Faker.Name
import GHC.Generics
import GHC.List as L
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
    userAddress :: Text,
    createdAt :: UTCTime,
    updatedAt :: String
  } deriving (Show, Generic, Eq)

instance ToJSON User
instance FromJSON User

allUsers :: IO [User]
allUsers = do
  dataName <- generateNonDeterministic $ listOf 3 name
  dataAddress <- generateNonDeterministic $ listOf 3  fullAddress
  nowTime <- getCurrentTime
  let updTime = formatTime defaultTimeLocale "%Y-%m-%d %H:%M:%S" nowTime
  let user1 = User (newUUID !! 0) (dataName !! 0) (dataAddress !! 0) (nowTime) (updTime)
  let user2 = User (newUUID !! 1) (dataName !! 1) (dataAddress !! 1) (nowTime) (updTime)
  let user3 = User (newUUID !! 2) (dataName !! 2) (dataAddress !! 2) (nowTime) (updTime)
  return [user1,user2,user3]

matchesId :: String -> User -> Bool
matchesId beam user = toString (userId user) == beam

routes :: ScottyM ()
routes = do
  get "/" rootAction
  get "/florida.json" floridaAction
  get "/kokua.json"   kokuaAction
  get "/manoa.json"   manoaAction
  get "/pahoa.json"   pahoaAction
  get "/users/:word"  usersAction

rootAction :: ActionM ()
rootAction = do
  html $ "<h1>Backend API server (haskell Scotty)</h1>"

floridaAction :: ActionM ()
floridaAction = do
  json $ object ["top news" .= ("Hurricane Milton weakens as it marches across central Florida" :: Text), "sports" .= ("Why 49ers should watch former UH linebacker Jeff Ulbrich, Jets interim coach" :: Text)]

kokuaAction :: ActionM ()
kokuaAction = do
  json Null

manoaAction :: ActionM ()
manoaAction = do
  users <- liftIO allUsers
  json users

pahoaAction :: ActionM ()
pahoaAction = do
  json $ object ["local" .= ("A combination bus hub and library project planned for Pahoa is on track to begin construction next year." :: Text), "today" .= ("Honolulu airport’s satisfaction score this year was 593 out of a possible 1,000" :: Text)]

usersAction :: ActionM ()
usersAction = do
  beam <- captureParam "word"
  users <- liftIO allUsers
  json (L.filter (matchesId beam) users)

start :: Int -> IO ()
start port = do
  print ("Starting Server at port " ++ show port)
  scotty port routes
