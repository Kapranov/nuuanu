{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE RecordWildCards #-}

module Platform.HTTP
  ( newUUID
  , start
  ) where

import Control.Monad()
import Control.Monad.IO.Class
import Data.Aeson             (Value (Null), object, (.=), FromJSON, ToJSON)
import Data.Text
import Data.Time              (getCurrentTime, UTCTime)
import Data.Time.Format
import Data.UUID
import Faker
import Faker.Address
import Faker.Combinators
import Faker.Name
import GHC.Generics
import GHC.List                as L
import System.Random
import Web.Scotty

instance ToJSON User
instance FromJSON User

data User =
  User {
    userId :: UUID,
    userName :: Text,
    userAddress :: Text,
    createdAt :: UTCTime,
    updatedAt :: String
  } deriving (Show, Generic, Eq)

newUUID :: [UUID]
newUUID =
  let seed = 123456789
      g0 = mkStdGen seed
      (u1, g1)  = random g0
      (u2, g2)  = random g1
      (u3, g3)  = random g2
      (u4, g4)  = random g3
      (u5, g5)  = random g4
      (u6, g6)  = random g5
      (u7, g7)  = random g6
      (u8, g8)  = random g7
      (u9, _g9) = random g8
  in [u1,u2,u3,u4,u5,u6,u7,u8,u9]

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
  get "/agent"       agentAction
  get "/avian.json"  avianAction
  get "/kokua.json"  kokuaAction
  get "/manoa.json"  manoaAction
  get "/oahuj.json"  oahujAction
  get "/oahus"       oahusAction
  get "/oahut.txt"   oahutAction
  get "/pahoa.json"  pahoaAction
  get "/reefs"       reefsAction
  get "/users/:word" usersAction

rootAction :: ActionM ()
rootAction = do
  html $ "<h1>Backend API server (haskell Scotty)</h1>"

agentAction :: ActionM ()
agentAction = do
  agent <- header "User-Agent"
  maybe (raise "User-Agent header not found!") text agent

avianAction :: ActionM ()
avianAction = do
  json $ object ["top news" .= ("Hurricane Milton weakens as it marches across central Florida" :: Text), "sports" .= ("Why 49ers should watch former UH linebacker Jeff Ulbrich, Jets interim coach" :: Text)]

kokuaAction :: ActionM ()
kokuaAction = do
  json Null

manoaAction :: ActionM ()
manoaAction = do
  users <- liftIO allUsers
  json users

oahujAction :: ActionM ()
oahujAction = do
  json $ object ["text" .= ("Hello, World!" :: Text)]

oahusAction :: ActionM ()
oahusAction = do
  html $ mconcat ["<h1>", "Hello, World!", "</h1>"]

oahutAction :: ActionM ()
oahutAction = do
  text "Hello, World!"

pahoaAction :: ActionM ()
pahoaAction = do
  json $ object ["local" .= ("A combination bus hub and library project planned for Pahoa is on track to begin construction next year." :: Text), "today" .= ("Honolulu airport’s satisfaction score this year was 593 out of a possible 1,000" :: Text)]

reefsAction :: ActionM ()
reefsAction = do
  pana <- queryParam "name"
  html $ mconcat ["<h1>Hello ", pana, "</h1>"]

usersAction :: ActionM ()
usersAction = do
  beam <- captureParam "word"
  users <- liftIO allUsers
  json (L.filter (matchesId beam) users)

start :: Int -> IO ()
start port = do
  print ("Starting Server at port " ++ show port)
  scotty port routes
