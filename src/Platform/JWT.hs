{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
module Platform.JWT
  ( main
  , maxSaveFileSize
  , saveKeyLength
  ) where

-- import Control.Monad (liftM)
-- import Data.Time.Clock.POSIX (getPOSIXTime)
-- import Jose.Jwt

import Control.Monad
import System.Random
import Auth.Bisque ( newSecret
                   , serializePublicKeyHex
                   , serializeSecretKeyHex
                   , toPublish
                   )

-- import Data.ByteString
-- import qualified Data.ByteString.Base64

-- import qualified Data.ByteString as B
-- import           Data.ByteString.Base64

-- Generate and Decode JWTs in Haskell with jose-jwt
-- specifications: JWE, JWK, JWS and JWT
-- JSON Object Signing and Encryption (JOSE)
-- JSON Web Algorithms (JWA)
-- JSON Web Encryption (JWE)
-- JSON Web Key (JWK)
-- JSON Web Signature (JWS)
-- JSON Web Token (JWT)
--
-- Access token
-- Claim  Value
-- sub    User ID
-- iat    The current time
-- exp    15 minutes
-- aud    "access" to identify this as an access token
--
-- Refresh token
-- Claim  Value
-- sub    User ID
-- iat    The current time
-- exp    1 day
-- aud    "refresh" to identify this as a refresh token
--

saveKeyLength :: Int
saveKeyLength = 8

maxSaveFileSize :: Int
maxSaveFileSize = 128 * 1024

random_char :: IO Char
random_char = do
  fmap toEnum (randomRIO (1,255)) :: IO Char

random_secret :: Int -> IO String
random_secret num = do
  replicateM num (randomRIO ('a','z'))

-- "The secret should be at least 32 characters long"
-- Generate bytes with randomly uniform values 0..255.
-- Returns the result in a binary with N bytes.
-- -spec strong_rand_bytes(N :: non_neg_integer()) -> binary().
-- random_string :: String
-- random_string :crypto.strong_rand_bytes(length) |> Base.encode64(padding: false) |> binary_part(0, length)

-- | Create a token
-- myBisque :: MySecretKey -> IO (Bisque Open Verified)
-- myBisque secretKey =
--   mkBisque secretKey [block|
--     user("1234");
--     check if operation("read");
--   |]

main :: IO ()
main = do
  genChar <- random_char
  genSecret <- random_secret 64
  print genChar
  print genSecret
  -- | Create a key pair 'SecretKey' and 'PublicKey'
  secretKey <- newSecret
  let publicKey = toPublish secretKey
  -- | Will print the hex-encoded secret key
  print $ serializeSecretKeyHex secretKey
  -- | Will print the hex-encoded public key
  print $ serializePublicKeyHex publicKey
--  currentTime <- liftM round getPOSIXTime
--  let expirationTime = currentTime + 864000 -- ten days
--  print expirationTime
--  let claims = mempty { unregisteredClaims = [("sub", String "public_key"), ("exp", Number $ fromIntegral expirationTime)] }
--  let key = Secret "private_key"
--  let token = encode [HS256] key claims
--  print token
