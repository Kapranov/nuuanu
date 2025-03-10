{-# LANGUAGE OverloadedStrings #-}
module Platform.Types ( CurrentUser
                      , Secret
                      , Token
                      , TokenError
                      , User
                      , UserId
                      , secret
                      ) where

import Data.Text (Text)
import Data.Time
-- import Data.ByteString (ByteString)
import Data.UUID

type CurrentUser = (Token, UserId)
type Token = Text
type UserId = UUID

newtype Secret = Secret Text deriving (Eq, Show)

data TokenError
  = TokenErrorUserIdNotFound
  | TokenErrorNotFound
  | TokenErrorExpired
  | TokenErrorMalformed String
  deriving (Eq, Show)

data User
  = User
  { userId        :: UUID
  , userFirstName :: String
  , userLastName  :: String
  , createdAt     :: UTCTime
  } deriving (Eq, Show)

secret :: Text -> Secret
secret = Secret
