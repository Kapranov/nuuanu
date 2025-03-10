{-# LANGUAGE OverloadedStrings #-}
-- {-# OPTIONS_GHC -fno-warn-name-shadowing #-}
-- {-# OPTIONS_GHC -fno-warn-unused-do-bind #-}
module Platform.JWT ( calculateExpiredTime
                    , encodeDecodeRS256
                    , encodeDecodeRS384
                    , encodeDecodeRS512
                    , getCurrentTimestamp
                    , main
                    , makeJwtClaims
                    , makePayload
                    , makeTokenRS256
                    , privateJwkRS256
                    , privateJwkRS384
                    , privateJwkRS512
                    , random_char
                    , random_secret
                    , verifyTokenRS256
                    ) where

import Control.Monad         (replicateM)
import Data.Text             ( Text
                             , pack
                             )
import Data.Text.Encoding    (encodeUtf8)
import Data.UUID             ( UUID
                             , toText
                             )
import Data.UUID.V4          (nextRandom)
import Jose.Jwa              ( Alg(Signed, Encrypted)
                             , Enc ( A128CBC_HS256
                                   , A128GCM
                                   , A192CBC_HS384
                                   , A192GCM
                                   , A256CBC_HS512
                                   , A256GCM
                                   )
                             , JweAlg ( A128KW
                                      , A192KW
                                      , A256KW
                                      , RSA1_5
                                      , RSA_OAEP
                                      , RSA_OAEP_256
                                      )
                             , JwsAlg( ES256
                                     , ES384
                                     , ES512
                                     , EdDSA
                                     , HS256
                                     , HS384
                                     , HS512
                                     , RS256
                                     , RS384
                                     , RS512
                                     )
                             )
import Jose.Jwe              as JWE
import Jose.Jwk              ( Jwk
                             --, Jwk(SymmetricJwk)
                             , KeyUse(Sig)
                             --, KeyId
                             , generateRsaKeyPair
                             , generateSymmetricKey
                             )
import Jose.Jws              as JWS
import Jose.Jwt              ( IntDate (..)
                             , Jwt (..)
                             , JwtClaims (..)
                             , JwtContent (..)
                             , JwtEncoding (..)
                             , JwtError (..)
                             , KeyId (..)
                             , Payload (..)
                             , decode
                             , encode
                             )
import System.Random         (randomRIO)
import Data.Time.Clock       ( getCurrentTime
                             , addUTCTime
                             )
import Data.Time.Clock.POSIX ( getPOSIXTime
                             , utcTimeToPOSIXSeconds
                             )
import Data.Aeson            as A
import Data.ByteString       (ByteString)
import Data.ByteString.Lazy  (toStrict)
import Crypto.PubKey.RSA     as RSA
import Crypto.PubKey.Ed25519 as Ed25519
import Crypto.PubKey.Ed448   as Ed448

-- import Crypto.PubKey.RSA     ( PrivateKey (..) , PublicKey (..))
-- import Crypto.PubKey.Ed25519 (SecretKey, PublicKey, toPublic, generateSecretKey)


-- | Generate and Decode JOSE-JWT
-- | specifications: JWA, JWE, JWK, JWS and JWT
-- | JOSE - JSON Object Signing and Encryption
-- |  JWA - JSON Web Algorithms
-- |  JWE - JSON Web Encryption
-- |  JWK - JSON Web Key
-- |  JWS - JSON Web Signature
-- |  JWT - JSON Web Token
--
-- | Jose.JWA
-- Alg -> Signed    -> JwsAlg -> None, HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, EdDSA
-- Alg -> Encrypted -> JweAlg -> RSA1_5, RSA_OAEP, RSA_OAEP_256, A128KW, A192KW, A256KW
-- Enc ->                        A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM, A256GCM
--
-- | Jose.JWE
-- jwkEncode
-- jwkDecode
-- rsaEncode
-- rsaDecode
--
-- | Jose.Jwk
-- EcCurve (..)
-- KeyUse (..)
-- KeyId
-- Jwk (..)
-- JwkSet (..)
-- isPublic
-- isPrivate
-- jwkId
-- jwkUse
-- canDecodeJws
-- canDecodeJwe
-- canEncodeJws
-- canEncodeJwe
-- generateRsaKeyPair
-- generateSymmetricKey
--
-- | Jose.Jws
-- jwkEncode
-- hmacEncode
-- hmacDecode
-- rsaEncode
-- rsaDecode
-- ecDecode
-- ed25519Encode
-- ed25519Decode
-- ed448Encode
-- ed448Decode
--
-- | Jose.Jwt
-- Jwt (..)
-- Jwe
-- Jws
-- JwtClaims (..)
-- JwtHeader (..)
-- JwsHeader (..)
-- JweHeader (..)
-- JwtContent (..)
-- JwtEncoding (..)
-- JwtError (..)
-- IntDate (..)
-- Payload (..)
-- KeyId (..)
-- parseHeader
-- encodeHeader
-- defJwsHdr
-- defJweHdr
--
-- | There are three classes of JWT Claim Names:
-- | Registered Claim Names - "registered claims"
-- | Public     Claim Names - "public claims"
-- | Private    Claim Names - "private claims"
--
-- | JWT Claims
-- aud  [Text] Audience
-- exp   Time  Expiration
-- iat   Time  Issued At
-- iss   Text  Issuer
-- jti   Text  JWT ID
-- nbf   Time  Not Before
-- sub   Text  Subject
--
-- | JOSE Header
-- type - Type Header parameter
-- cty  - Content Type  Header parameter
-- | Access token
-- Claim  Value
-- sub    User ID
-- iat    The current time
-- exp    15 minutes
-- aud    "access" to identify this as an access token
--
-- | Refresh token
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

getCurrentTimestamp :: IO Integer
getCurrentTimestamp = (round `fmap` getPOSIXTime)

calculateExpiredTime :: Integer -> Integer
calculateExpiredTime ts = ts + 864000

privateJwkRS256 :: Text -> IO Jwk
privateJwkRS256 key = do
  (_, privKey) <- generateRsaKeyPair 256 (KeyId key) Sig (Just (Signed RS256))
  return privKey

privateJwkRS384 :: Text -> IO Jwk
privateJwkRS384 key = do
  (_, privKey) <- generateRsaKeyPair 384 (KeyId key) Sig (Just (Signed RS384))
  return privKey

privateJwkRS512 :: Text -> IO Jwk
privateJwkRS512 key = do
  (_, privKey) <- generateRsaKeyPair 512 (KeyId key) Sig (Just (Signed RS512))
  return privKey

makeJwtClaims :: UUID -> IO JwtClaims
makeJwtClaims userIdx = do
  currentUTC <- getCurrentTime
  let currentTime = IntDate $ utcTimeToPOSIXSeconds $ currentUTC
  let laterDate = IntDate $ utcTimeToPOSIXSeconds $ addUTCTime (60 * 60 * 24 * 14) currentUTC
  return $ JwtClaims Nothing
                     (Just $ toText userIdx)
                     Nothing
                     (Just laterDate)
                     Nothing
                     (Just currentTime)
                     Nothing

makePayload :: JwtClaims -> Payload
makePayload claims = Claims $ toStrict $ A.encode claims

makeTokenRS256 :: UUID -> Jwk -> JwsAlg -> IO ()
makeTokenRS256 userIdx jwk jwsAlg = do
  claims <- makeJwtClaims userIdx
  let encAlg  = JwsEncoding jwsAlg
      payload = makePayload claims
  eitherJwt <- Jose.Jwt.encode [jwk] encAlg payload
  case eitherJwt of
    Left err -> print err
    Right (Jwt {unJwt = token}) -> print token

verifyTokenRS256 :: Text -> Jwk -> IO Bool
verifyTokenRS256 token jwk = do
  let encAlg  = JwsEncoding RS256
  let jwt = (Jwt {unJwt = (encodeUtf8 token)})
  eitherContent <- Jose.Jwt.decode [jwk] (Just encAlg) (unJwt jwt)
  case eitherContent of
    Left  (KeyError _)     -> pure False
    Left  (BadAlgorithm _) -> pure False
    Left  (BadDots _)      -> pure False
    Left  (BadHeader _)    -> pure False
    Left  (BadClaims)      -> pure False
    Left  (BadSignature)   -> pure False
    Left  (BadCrypto)      -> pure False
    Left  (Base64Error _)  -> pure False
    Right (Jws (_, _))     -> pure True
    Right (Unsecured _)    -> pure True
    Right (Jwe _)          -> pure True

encodeDecodeRS256 :: UUID -> Text -> IO ()
encodeDecodeRS256 userIdx key = do
  jwk    <- privateJwkRS256 key
  claims <- makeJwtClaims userIdx
  let encAlg  = JwsEncoding RS256
      payload = makePayload claims
  eitherJwt <- Jose.Jwt.encode [jwk] encAlg payload
  case eitherJwt of
    Left err -> print err
    Right jwt -> do
      eitherContent <- Jose.Jwt.decode [jwk] (Just encAlg) (unJwt jwt)
      case eitherContent of
        Left  (KeyError ta)     -> print ta
        Left  (BadAlgorithm tb) -> print tb
        Left  (BadDots tc)      -> print tc
        Left  (BadHeader td)    -> print td
        Left  (BadClaims)       -> return ()
        Left  (BadSignature)    -> return ()
        Left  (BadCrypto)       -> return ()
        Left  (Base64Error th)  -> print th
        Right (Jws (_, bs))     -> print bs
        Right (Unsecured tx)    -> print tx
        Right (Jwe tz)          -> print tz

encodeDecodeRS384 :: UUID -> Text -> IO ()
encodeDecodeRS384 userIdx key = do
  jwk    <- privateJwkRS384 key
  claims <- makeJwtClaims userIdx
  let encAlg  = JwsEncoding RS384
      payload = makePayload claims
  eitherJwt <- Jose.Jwt.encode [jwk] encAlg payload
  case eitherJwt of
    Left err -> print err
    Right jwt -> do
      eitherContent <- Jose.Jwt.decode [jwk] (Just encAlg) (unJwt jwt)
      case eitherContent of
        Left  (KeyError ta)     -> print ta
        Left  (BadAlgorithm tb) -> print tb
        Left  (BadDots tc)      -> print tc
        Left  (BadHeader td)    -> print td
        Left  (BadClaims)       -> return ()
        Left  (BadSignature)    -> return ()
        Left  (BadCrypto)       -> return ()
        Left  (Base64Error th)  -> print th
        Right (Jws (_, bs))     -> print bs
        Right (Unsecured tx)    -> print tx
        Right (Jwe tz)          -> print tz

encodeDecodeRS512 :: UUID -> Text -> IO ()
encodeDecodeRS512 userIdx key = do
  jwk    <- privateJwkRS512 key
  claims <- makeJwtClaims userIdx
  let encAlg  = JwsEncoding RS512
      payload = makePayload claims
  eitherJwt <- Jose.Jwt.encode [jwk] encAlg payload
  case eitherJwt of
    Left err -> print err
    Right jwt -> do
      eitherContent <- Jose.Jwt.decode [jwk] (Just encAlg) (unJwt jwt)
      case eitherContent of
        Left  (KeyError ta)     -> print ta
        Left  (BadAlgorithm tb) -> print tb
        Left  (BadDots tc)      -> print tc
        Left  (BadHeader td)    -> print td
        Left  (BadClaims)       -> return ()
        Left  (BadSignature)    -> return ()
        Left  (BadCrypto)       -> return ()
        Left  (Base64Error th)  -> print th
        Right (Jws (_, bs))     -> print bs
        Right (Unsecured tx)    -> print tx
        Right (Jwe tz)          -> print tz

myClaims :: ByteString
myClaims = "helloWorld"

myKeyId :: Text
myKeyId = "My Keywrap Key"

forKeyId :: ByteString
forKeyId = "My Keywrap Key"

myInt :: Int
myInt = 16

rsaModulus :: Integer
rsaModulus = 20446702916744654562596343388758805860065209639960173505037453331270270518732245089773723012043203236097095623402044690115755377345254696448759605707788965848889501746836211206270643833663949992536246985362693736387185145424787922241585721992924045675229348655595626434390043002821512765630397723028023792577935108185822753692574221566930937805031155820097146819964920270008811327036286786392793593121762425048860211859763441770446703722015857250621107855398693133264081150697423188751482418465308470313958250757758547155699749157985955379381294962058862159085915015369381046959790476428631998204940879604226680285601

rsaExponent :: Integer
rsaExponent = 65537

rsaPrivateExponent :: Integer
rsaPrivateExponent = 2358310989939619510179986262349936882924652023566213765118606431955566700506538911356936879137503597382515919515633242482643314423192704128296593672966061810149316320617894021822784026407461403384065351821972350784300967610143459484324068427674639688405917977442472804943075439192026107319532117557545079086537982987982522396626690057355718157403493216553255260857777965627529169195827622139772389760130571754834678679842181142252489617665030109445573978012707793010592737640499220015083392425914877847840457278246402760955883376999951199827706285383471150643561410605789710883438795588594095047409018233862167884701

rsaPrivateKey :: RSA.PrivateKey
rsaPrivateKey = RSA.PrivateKey
  { RSA.private_pub = rsaPublicKey
  , RSA.private_d = rsaPrivateExponent
  , RSA.private_q = 0
  , RSA.private_p = 0
  , RSA.private_dP = 0
  , RSA.private_dQ = 0
  , RSA.private_qinv = 0
  }

rsaPublicKey :: RSA.PublicKey
rsaPublicKey = RSA.PublicKey
  { RSA.public_size = 256
  , RSA.public_n = rsaModulus
  , RSA.public_e = rsaExponent
  }

main :: IO ()
main = do
  -- | Generate custom secretKey
  putStrLn $ "---| BEGIN |-------------------------------------"
  print $ saveKeyLength
  print $ maxSaveFileSize
  random_char >>= print
  random_secret 64 >>= print
  -- | Generate Jose JWT
  putStrLn $ "---| BEGIN |-------------------------------------\n\n\n"
  currentTime <- getCurrentTimestamp
  userIdx <- nextRandom
  let secretMacKey = encodeUtf8 $ pack "my_private_key"
  let expirationTime = calculateExpiredTime currentTime
  let claims = JwtClaims { jwtAud = Nothing
                         , jwtExp = Just $ IntDate $ fromIntegral expirationTime
                         , jwtIat = Just $ IntDate $ fromIntegral currentTime
                         , jwtIss = Nothing
                         , jwtJti = Nothing
                         , jwtNbf = Nothing
                         , jwtSub = Just $ toText userIdx
                         }
  let _tokenHS256 = JWS.hmacEncode HS256 secretMacKey myClaims
  let _tokenHS384 = JWS.hmacEncode HS384 secretMacKey myClaims
  let _tokenHS512 = JWS.hmacEncode HS512 secretMacKey myClaims

  Right (Jwt _tokenRS256) <- JWS.rsaEncode RS256 rsaPrivateKey myClaims
  Right (Jwt _tokenRS384) <- JWS.rsaEncode RS384 rsaPrivateKey myClaims
  Right (Jwt _tokenRS512) <- JWS.rsaEncode RS512 rsaPrivateKey myClaims

  sk_for_Ed25519 <- Ed25519.generateSecretKey
  sk_for_Ed448 <- Ed448.generateSecretKey

  let pk_for_Ed25519 = Ed25519.toPublic sk_for_Ed25519
  let pk_for_Ed448 = Ed448.toPublic sk_for_Ed448

  let _tokenEd25519 = ed25519Encode sk_for_Ed25519 pk_for_Ed25519 myClaims
  let _tokenEd448 = ed448Encode sk_for_Ed448 pk_for_Ed448 myClaims

  putStrLn $ "---| BEGIN Token ES256 A128KW A128CBC_HS256 |---------"
  keyES256 <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256))
  Right (Jwt jwt1) <- JWE.jwkEncode A128KW A128CBC_HS256 keyES256 (Claims myClaims)
  Right (Jwe (_, msg1)) <- JWE.jwkDecode keyES256 jwt1
  if myClaims == msg1 then print msg1 else return ()
  Right (Jwt jwt2) <- JWE.rsaEncode RSA_OAEP A256GCM rsaPublicKey myClaims
  Right (_, msg2) <- JWE.rsaDecode rsaPrivateKey jwt2
  if myClaims == msg2 then print msg2 else return ()
  case JWS.hmacEncode HS256 forKeyId myClaims of
    Right (Jwt jwt3) ->
      case JWS.hmacDecode forKeyId jwt3 of
        Right (_, val) ->
          if myClaims == val then print val else return ()
        Left err ->
          print err
    Left err ->
      print err
  putStrLn $ "---| END   Token |------------------------------------\n"
  let _ = JWS.hmacEncode HS256 forKeyId myClaims
  let _ = JWS.hmacEncode HS384 forKeyId myClaims
  let _ = JWS.hmacEncode HS512 forKeyId myClaims
  _ <- JWE.rsaEncode RSA1_5       A128CBC_HS256 rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA1_5       A128GCM       rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA1_5       A192CBC_HS384 rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA1_5       A192GCM       rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA1_5       A256CBC_HS512 rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA1_5       A256GCM       rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP     A128CBC_HS256 rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP     A128GCM       rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP     A192CBC_HS384 rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP     A192GCM       rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP     A256CBC_HS512 rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP     A256GCM       rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP_256 A128CBC_HS256 rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP_256 A128GCM       rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP_256 A192CBC_HS384 rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP_256 A192GCM       rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP_256 A256CBC_HS512 rsaPublicKey myClaims
  _ <- JWE.rsaEncode RSA_OAEP_256 A256GCM       rsaPublicKey myClaims
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed ES512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed EdDSA)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed HS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS256)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS384)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A128KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A128KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A128KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A128KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A128KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A128KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A192KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A192KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A192KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A192KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A192KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A192KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A256KW       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A256KW       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A256KW       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A256KW       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A256KW       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode A256KW       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA1_5       A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA1_5       A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA1_5       A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA1_5       A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA1_5       A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA1_5       A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP     A256GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Signed RS512)) >>= \k -> JWE.jwkEncode RSA_OAEP_256 A256GCM       k (Claims myClaims)

  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A128KW)) >>= \k -> JWE.jwkEncode A128KW A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A128KW)) >>= \k -> JWE.jwkEncode A128KW A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A128KW)) >>= \k -> JWE.jwkEncode A128KW A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A128KW)) >>= \k -> JWE.jwkEncode A128KW A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A128KW)) >>= \k -> JWE.jwkEncode A128KW A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A128KW)) >>= \k -> JWE.jwkEncode A128KW A256GCM       k (Claims myClaims)

  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A192KW)) >>= \k -> JWE.jwkEncode A128KW A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A192KW)) >>= \k -> JWE.jwkEncode A128KW A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A192KW)) >>= \k -> JWE.jwkEncode A128KW A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A192KW)) >>= \k -> JWE.jwkEncode A128KW A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A192KW)) >>= \k -> JWE.jwkEncode A128KW A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A192KW)) >>= \k -> JWE.jwkEncode A128KW A256GCM       k (Claims myClaims)

  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A256KW)) >>= \k -> JWE.jwkEncode A128KW A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A256KW)) >>= \k -> JWE.jwkEncode A128KW A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A256KW)) >>= \k -> JWE.jwkEncode A128KW A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A256KW)) >>= \k -> JWE.jwkEncode A128KW A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A256KW)) >>= \k -> JWE.jwkEncode A128KW A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted A256KW)) >>= \k -> JWE.jwkEncode A128KW A256GCM       k (Claims myClaims)

  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP)) >>= \k -> JWE.jwkEncode A128KW A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP)) >>= \k -> JWE.jwkEncode A128KW A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP)) >>= \k -> JWE.jwkEncode A128KW A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP)) >>= \k -> JWE.jwkEncode A128KW A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP)) >>= \k -> JWE.jwkEncode A128KW A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP)) >>= \k -> JWE.jwkEncode A128KW A256GCM       k (Claims myClaims)

  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP_256)) >>= \k -> JWE.jwkEncode A128KW A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP_256)) >>= \k -> JWE.jwkEncode A128KW A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP_256)) >>= \k -> JWE.jwkEncode A128KW A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP_256)) >>= \k -> JWE.jwkEncode A128KW A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP_256)) >>= \k -> JWE.jwkEncode A128KW A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA_OAEP_256)) >>= \k -> JWE.jwkEncode A128KW A256GCM       k (Claims myClaims)

  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA1_5)) >>= \k -> JWE.jwkEncode A128KW A128CBC_HS256 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA1_5)) >>= \k -> JWE.jwkEncode A128KW A128GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA1_5)) >>= \k -> JWE.jwkEncode A128KW A192CBC_HS384 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA1_5)) >>= \k -> JWE.jwkEncode A128KW A192GCM       k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA1_5)) >>= \k -> JWE.jwkEncode A128KW A256CBC_HS512 k (Claims myClaims)
  _ <- generateSymmetricKey myInt (KeyId myKeyId) Sig (Just (Encrypted RSA1_5)) >>= \k -> JWE.jwkEncode A128KW A256GCM       k (Claims myClaims)

  print claims
  putStrLn $ "\n\n---| END   |-------------------------------------"
