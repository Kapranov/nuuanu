{-# LANGUAGE BlockArguments        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE PackageImports        #-}
{-# LANGUAGE QuasiQuotes           #-}
{-# OPTIONS_GHC -Wall              #-}
module Platform.JWT ( main
                    , maxSaveFileSize
                    , saveKeyLength
                    ) where

import Auth.Bisque ( Bisque
                   , BisqueEncoding (RawBytes, UrlBase64)
                   , Open
                   , OpenOrSealed
                   , ParserConfig (..)
                   , PublicKey
                   , Sealed
                   , SecretKey
                   , Verified
                   , addBlock
                   , authorizeBisque
                   , authorizer
                   , block
                   , encodeHex
                   , fromRevocationList
                   , getRevocationIds
                   , getSingleVariableValue
                   , getVerifiedBisquePublicKey
                   , mkBisque
                   , newPublic
                   , newSecret
                   , parse
                   , parseB64
                   , parsePublicKey
                   , parsePublicKeyHex
                   , parseSecretKey
                   , parseSecretKeyHex
                   , parseWith
                   , query
                   , queryAuthorizerFacts
                   , seal
                   , serialize
                   , serializeB64
                   , serializePublicKey
                   , serializePublicKeyHex
                   , serializeSecretKey
                   , serializeSecretKeyHex
                   , toPublic
                   )

import "crypton" Crypto.Random                        (getRandomBytes)
import Control.Monad                                  ( liftM,
                                                      replicateM
                                                      )
import Control.Monad.Except                           ( MonadError
                                                      , throwError
                                                      )
import Data.ByteString                                (ByteString)
import qualified Data.ByteString        as ByteString ( readFile
                                                      , writeFile
                                                      )
import qualified Data.ByteString.Base64 as Base64     ( decode
                                                      , encode
                                                      )
import Data.Foldable                                  (Foldable)
import Data.Functor                                   (($>))
import Data.Int                                       (Int64)
import Data.List.NonEmpty                             (toList)
import Data.Map.Strict (Map)
import qualified Data.Map.Strict                      as Map
import Data.Text (Text)
import qualified Data.Text                            as Text ( pack
                                                              , unpack
                                                              )
import Data.Text.Display
import Data.Time
import Data.Time.Calendar                             (diffDays)
import Data.Time.Clock                                ( UTCTime
                                                      , getCurrentTime
                                                      , nominalDiffTimeToSeconds
                                                      , utctDay
                                                      )
import Data.Time.Clock.POSIX                          ( getPOSIXTime
                                                      , utcTimeToPOSIXSeconds
                                                      )
import Data.UUID
import GHC.Generics
import Data.UUID
import GHC.Generics
import Platform.HTTP                                  (newUUID)
import Prelude hiding (lookup)
import System.OsPath.Posix
import System.Posix.Files.PosixString
import System.Random
-- import Jose.Jwt

-- | Generate and Decode JWTs in Haskell with jose-jwt
-- | specifications: JWE, JWK, JWS and JWT
-- | JSON Object Signing and Encryption (JOSE)
-- | JSON Web Algorithms (JWA)
-- | JSON Web Encryption (JWE)
-- | JSON Web Key (JWK)
-- | JSON Web Signature (JWS)
-- | JSON Web Token (JWT)
--
-- | Access token
-- Claim  Value
-- sub    User ID
-- iat    The current time
-- exp    15 minutes
-- aud    "access" to identify this as an access token
--
-- | Refresh token
-- Claim  Value
-- sub    User ID
-- iat    The current time
-- exp    1 day
-- aud    "refresh" to identify this as a refresh token

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

-- | BEGIN Bisque Token Authorization System
--
-- | 1,2,3. Create a root key (keypair - private/public keys)
genKeys :: IO ()
genKeys = do
  sk <- newSecret
  let pk = toPublic sk
  let sk' = serializeSecretKeyHex sk
  let pk' = serializePublicKeyHex pk
  putStrLn "Generating a new random keypair"
  print ("Private key: " <> sk')
  print ("Public  key: " <> pk')

-- | 4. Create a token
buildToken :: SecretKey -> Text -> IO (Bisque Open Verified)
buildToken sk value = do
  now <- getCurrentTime
  let expire = addUTCTime 36000 now
  mkBisque sk [block|user_id(${value});check if time($time),$time < ${expire};|]

-- | 5. Create an authorize
myCheck :: Text -> Bisque p Verified -> IO Bool
myCheck value bisque = do
  now <- getCurrentTime
  result <- authorizeBisque bisque [authorizer|time(${now});allow if user_id(${value});|]
  case result of
    Left a  -> pure False
    Right _ -> pure True

-- | 6. Attenuate a token
addTTL :: UTCTime -> Bisque Open c -> IO (Bisque Open c)
addTTL ttl bisque = addBlock [block|check if time($time),$time < ${ttl};|] bisque

-- | 7. Seal a token
sealBisque :: Bisque Open c -> Bisque Sealed c
sealBisque bisque = seal bisque

-- | 8. Reject revoked tokens
viaParseWith :: Either a b -> IO Bool
viaParseWith p = do
  case p of
    Left _ -> pure False
    Right _ -> pure True

encodeBisque :: SecretKey -> Text -> UTCTime -> IO ByteString
encodeBisque sk value ttl = do
  now <- getCurrentTime
  let expire = addUTCTime 36000 now
  let authority = [block|user_id(${value});check if current_time($time),$time < ${expire};|]
  bisque <- mkBisque sk authority
  let block1 = [block|check if current_time($time),$time < ${ttl};|]
  newBisque <- addBlock block1 bisque
  pure $ serialize newBisque

encodeBisque64 :: SecretKey -> Text -> UTCTime -> IO ByteString
encodeBisque64 sk value ttl = do
  now <- getCurrentTime
  let expire = addUTCTime 36000 now
  let authority = [block|user_id(${value});check if current_time($time),$time < ${expire};|]
  bisque <- mkBisque sk authority
  let block1 = [block|check if current_time($time),$time < ${ttl};|]
  newBisque <- addBlock block1 bisque
  pure $ serializeB64 newBisque

verification :: PublicKey -> ByteString -> Text -> IO Bool
verification pk serialized value = do
  now <- getCurrentTime
  bisque <- either (fail . show) pure $ parse pk serialized
  let authorizer' = [authorizer|current_time(${now});allow if user_id(${value});|]
  result <- authorizeBisque bisque authorizer'
  case result of
    Left e  -> print e $> False
    Right _ -> pure True

verification64 :: PublicKey -> ByteString -> Text -> IO Bool
verification64 pk serialized value = do
  now <- getCurrentTime
  bisque <- either (fail . show) pure $ parseB64 pk serialized
  let authorizer' = [authorizer|current_time(${now});allow if user_id(${value});|]
  result <- authorizeBisque bisque authorizer'
  case result of
    Left e  -> print e $> False
    Right _ -> pure True

parseBisque :: PublicKey -> ByteString -> IO Bool
parseBisque pk encodedBisque =  do
  let parsingOptions =
        ParserConfig
          { encoding = RawBytes
          , isRevoked = const $ pure False
          , getPublicKey = pure pk
          }
  result <- parseWith parsingOptions encodedBisque
  viaParseWith result

parseBisque64 :: PublicKey -> ByteString -> IO Bool
parseBisque64 pk encodedBisque =  do
  let parsingOptions =
        ParserConfig
          { encoding = UrlBase64
          , isRevoked = const $ pure False
          , getPublicKey = pure pk
          }
  result <- parseWith parsingOptions encodedBisque
  viaParseWith result

pullRevocationIds :: (Bisque Open Verified) -> [Text]
pullRevocationIds bisque = [encodeHex x | x <- toList (getRevocationIds bisque)]

parseBisque64' :: (Foldable t) => PublicKey -> ByteString -> t ByteString -> IO Bool
parseBisque64' pk encodedBisque revokedIds = do
  let parsingOptions =
        ParserConfig
          { encoding = UrlBase64
          , getPublicKey = \_ -> pk
          , isRevoked = fromRevocationList revokedIds
          }
  result <- parseWith parsingOptions encodedBisque
  case result of
    Left _ -> pure False
    Right _ -> pure True

-- | 9. Query data from the authorizer
checkBisque :: Bisque proof Verified -> Text -> IO Text
checkBisque bisque value = do
  now <- getCurrentTime
  result <- authorizeBisque bisque [authorizer|time(${now});allow if user_id(${value});|]
  case result of
    Left err -> pure "msg#1 The user ID you entered does not exist"
    Right success ->
      case getSingleVariableValue (queryAuthorizerFacts success [query|user_id($user_id)|]) "user_id" of
        Just userId -> pure userId
        Nothing -> pure "msg#2 The user ID you entered does not exist"

-- | 10. Inspect a token    - `NONE`
--
-- | END Bisque Token Authorization System

nanosSinceEpoch :: UTCTime -> Int64
nanosSinceEpoch =
  floor . (1e9 *) . nominalDiffTimeToSeconds . utcTimeToPOSIXSeconds

data User = User
  { userId        :: Int
  , userFirstName :: String
  , userLastName  :: String
  , createdAt     :: UTCTime
  } deriving (Eq, Show)

allUsers :: [User]
allUsers = [ User 1 "Bob"       "Price"   (UTCTime (fromGregorian 2016 7 18) (timeOfDayToTime $ TimeOfDay 1 15 43))
           , User 2 "Brandon"   "Darby"   (UTCTime (fromGregorian 2017 5 17) (timeOfDayToTime $ TimeOfDay 2 48 38))
           , User 3 "David"     "Pollak"  (UTCTime (fromGregorian 2018 2 16) (timeOfDayToTime $ TimeOfDay 3 16 29))
           , User 4 "Elizabeth" "Weibel"  (UTCTime (fromGregorian 2019 4 15) (timeOfDayToTime $ TimeOfDay 4 29 11))
           , User 5 "Joshua"    "Klein"   (UTCTime (fromGregorian 2020 2 14) (timeOfDayToTime $ TimeOfDay 5 30 56))
           , User 6 "Olivia"    "Rondeau" (UTCTime (fromGregorian 2021 8 13) (timeOfDayToTime $ TimeOfDay 6 42 31))
           , User 7 "Pam"       "Key"     (UTCTime (fromGregorian 2022 3 12) (timeOfDayToTime $ TimeOfDay 7 28 47))
           , User 8 "Paul"      "Bois"    (UTCTime (fromGregorian 2023 6 11) (timeOfDayToTime $ TimeOfDay 8 54 21))
           , User 9 "Rebecca"   "Mansour" (UTCTime (fromGregorian 2024 1 10) (timeOfDayToTime $ TimeOfDay 9 21 38))
           ]

idx_userId :: [UUID]
idx_userId = newUUID

newtype UserId = UserId UUID deriving (Eq, Show)

users :: [(Text, UserId)]
users =
  [ ("admin@example.org", UserId $ read $ show $ idx_userId !! 0)
  , ("test1@example.org", UserId $ read $ show $ idx_userId !! 1)
  , ("test2@example.org", UserId $ read $ show $ idx_userId !! 2)
  , ("test3@example.org", UserId $ read $ show $ idx_userId !! 3)
  , ("test4@example.org", UserId $ read $ show $ idx_userId !! 4)
  , ("test5@example.org", UserId $ read $ show $ idx_userId !! 5)
  , ("test6@example.org", UserId $ read $ show $ idx_userId !! 6)
  , ("test7@example.org", UserId $ read $ show $ idx_userId !! 7)
  , ("test8@example.org", UserId $ read $ show $ idx_userId !! 8)
  ]

getUsers :: Map Text UserId
getUsers = Map.fromList users

getUserId :: String -> String
getUserId email = do
  let found = Map.lookup (Text.pack email) getUsers
  case found of
    Just (UserId idx) ->
      show idx
    Nothing ->
      "The user ID you entered does not exist"

getUserNum :: Int -> Maybe UUID
getUserNum num | num < 9 =
  case Map.elemAt num getUsers of
    (_email,UserId uuid) -> Just uuid
getUserNum _ = Nothing

admin :: UserId
admin = UserId $ read $ show $ idx_userId !! 0

data Secret = Secret ByteString deriving (Eq, Show)

generateSecret :: IO Secret
generateSecret = Secret <$> getRandomBytes 32

writeSecret :: IO ByteString
writeSecret = do
  let secret = generateSecret
  (Secret bytes) <- secret
  let pwd = Base64.encode bytes
  pure pwd

readSecret :: ByteString -> IO Secret
readSecret pwd = do
  case Base64.decode pwd of
    Left err -> error err
    Right bytes -> return $ Secret bytes

writePathSecret :: FilePath -> Secret -> IO ()
writePathSecret path (Secret bytes) = ByteString.writeFile path (Base64.encode bytes)

readPathSecret :: FilePath -> IO Secret
readPathSecret path = do
  secret <- ByteString.readFile path
  case Base64.decode secret of
    Left err -> error err
    Right bytes -> return $ Secret bytes

main :: IO ()
main = do
  -- BEGIN Dates and Times
  getCurrentTime >>= return.(formatTime defaultTimeLocale "%D %H:%M:%S") >>= putStrLn.show
  let epoch = read "1970-01-01 00:00:00 UTC"
  getCurrentTime >>= print
  now <- getCurrentTime :: IO UTCTime
  print (nanosSinceEpoch now)
  putStrLn ("The time is " ++ show now)
  print $ (utctDay now) `diffDays` (utctDay epoch)
  today <- fmap utctDay getCurrentTime
  let (year, _, _) = toGregorian today
  let days = diffDays today (fromGregorian year 0 0)
  putStrLn $ "Today is day " ++ show days ++ " of the current year"
  -- Generate custom secretKey
  genChar <- random_char
  genSecret <- random_secret 64
  print genChar
  print genSecret
  -- | Bisque - create a key pair 'SecretKey' and 'PublicKey'
  let userUUID = toText $ newUUID !! 0
  sk <- newSecret
  token <- buildToken sk userUUID
  let pk = toPublic sk
  let bisqueBs = serialize token
  result <- authorizeBisque token [authorizer|allow if user_id(${userUUID});|]
  print bisqueBs
  res <- checkBisque token userUUID
  print res
  putStrLn $ "---| BEGIN singleBlock |-------------------------------------"
  print result
  putStrLn $ "---| END singleBlock   |-------------------------------------"
  -- | Will print the hex-encoded secret key
  print $ serializeSecretKeyHex sk
  -- | Will print the hex-encoded public key
  print $ serializePublicKeyHex pk
  -- | The current time creates
  currentTime <- liftM round getPOSIXTime
  let expirationTime = currentTime + 864000
  -- | Will print round up numbers to integer
  print $ show $ expirationTime
  -- let claims = mempty { unregisteredClaims = [("sub", String "public_key"), ("exp", Number $ fromIntegral expirationTime)] }
  -- let key = Secret "private_key"
  -- let token = encode [HS256] key claims
  -- print token
