{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
module Spec.Auth.Kailua.Crypto (specs) where

import Auth.Kailua.Crypto
import Data.ByteString               (ByteString)
import Data.List.NonEmpty            (NonEmpty ((:|)))
import qualified Data.List.NonEmpty  as NE
import Test.Tasty
import Test.Tasty.HUnit

data Token = Token
  { payload :: Blocks
  , privKey :: SecretKey
  }

data SealedToken = SealedToken
  { payload :: Blocks
  , sig     :: Signature
  }

alterPayload :: (Blocks -> Blocks) -> Token -> Token
alterPayload f Token{..} = Token { payload = f payload, ..}

appendSigned :: Token -> SecretKey -> ByteString -> IO Token
appendSigned t@Token{payload} eSk p = do
  let (_, _, lastPk, _) = NE.last payload
  (signedBlock, privKey) <- signExternalBlock (privKey t) eSk lastPk p
  pure Token
    { payload = snocNE payload signedBlock
    , privKey
    }

alterPayloadSealed :: (Blocks -> Blocks) -> SealedToken -> SealedToken
alterPayloadSealed f SealedToken{..} = SealedToken { payload = f payload, ..}

append :: Token -> ByteString -> IO Token
append t@Token{payload} p = do
  (signedBlock, privKey) <- signBlock (privKey t) p Nothing
  pure Token
    { payload = snocNE payload signedBlock
    , privKey
    }

signToken :: ByteString -> SecretKey -> IO Token
signToken p sk = do
  (signedBlock, privKey) <- signBlock sk p Nothing
  pure Token
    { payload = pure signedBlock
    , privKey
    }

seal :: Token -> SealedToken
seal Token{payload,privKey} =
  let lastBlock = NE.last payload
  in SealedToken
      { sig = getSignatureProof lastBlock privKey
      , payload
      }

snocNE :: NonEmpty a -> a -> NonEmpty a
snocNE (h :| t) e = h :| (t <> [e])

verifyToken :: Token -> PublicKey -> Bool
verifyToken Token{payload, privKey} rootPk =
  let blocks = payload
      sigChecks = verifyBlocks blocks rootPk
      lastCheck = verifySecretProof privKey (NE.last payload)
  in sigChecks && lastCheck

verifySealedToken :: SealedToken -> PublicKey -> Bool
verifySealedToken SealedToken{payload, sig} rootPk =
  let blocks = payload
      sigChecks = verifyBlocks blocks rootPk
      lastCheck = verifySignatureProof sig (NE.last payload)
  in sigChecks && lastCheck

specs :: TestTree
specs = testGroup "new kailua crypto"
  [ testGroup "signature algorithm - normal"
      [ singleBlockRoundtrip
      , multiBlockRoundtrip
      , tamperedAuthority
      , tamperedBlock
      , removedBlock
      ]
  , testGroup "signature algorithm - sealed"
      [ singleBlockRoundtripSealed
      , multiBlockRoundtripSealed
      , tamperedAuthoritySealed
      , tamperedBlockSealed
      , removedBlockSealed
      ]
  , testGroup "external signatures"
      [ multiBlockRoundtripWithExternal
      , invalidExternalSig
      ]
  ]

singleBlockRoundtrip :: TestTree
singleBlockRoundtrip = testCase "Single block roundtrip" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  let res = verifyToken token pk
  res @?= True

multiBlockRoundtrip :: TestTree
multiBlockRoundtrip = testCase "Multi block roundtrip" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- append token "block1"
  let res = verifyToken attenuated pk
  res @?= True

tamperedAuthority :: TestTree
tamperedAuthority = testCase "Tampered authority" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- append token "block1"
  let tamper ((_, s, _pk, eS) :| o) = ("tampered", s, pk, eS) :| o
      tampered = alterPayload tamper attenuated
  let res = verifyToken tampered pk
  res @?= False

tamperedBlock :: TestTree
tamperedBlock = testCase "Tampered block" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- append token "block1"
  let tamper (h :| _) = h :| []
      tampered = alterPayload tamper attenuated
  let res = verifyToken tampered pk
  res @?= False

removedBlock :: TestTree
removedBlock = testCase "Removed block" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- append token "block1"
  let tamper (h :| _) = h :| []
      tampered = alterPayload tamper attenuated
  let res = verifyToken tampered pk
  res @?= False

singleBlockRoundtripSealed :: TestTree
singleBlockRoundtripSealed = testCase "Single block roundtrip" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- seal <$> signToken content sk
  let res = verifySealedToken token pk
  res @?= True

multiBlockRoundtripSealed :: TestTree
multiBlockRoundtripSealed = testCase "Multi block roundtrip" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- seal <$> append token "block1"
  let res = verifySealedToken attenuated pk
  res @?= True

tamperedAuthoritySealed :: TestTree
tamperedAuthoritySealed = testCase "Tampered authority" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- seal <$> append token "block1"
  let tamper ((_, s, _pk, eS) :| o) = ("tampered", s, pk, eS) :| o
      tampered = alterPayloadSealed tamper attenuated
  let res = verifySealedToken tampered pk
  res @?= False

tamperedBlockSealed :: TestTree
tamperedBlockSealed = testCase "Tampered block" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- seal <$> append token "block1"
  let tamper (h :| _) = h :| []
      tampered = alterPayloadSealed tamper attenuated
  let res = verifySealedToken tampered pk
  res @?= False

removedBlockSealed :: TestTree
removedBlockSealed = testCase "Removed block" $ do
  sk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- seal <$> append token "block1"
  let tamper (h :| _) = h :| []
      tampered = alterPayloadSealed tamper attenuated
  let res = verifySealedToken tampered pk
  res @?= False

multiBlockRoundtripWithExternal :: TestTree
multiBlockRoundtripWithExternal = testCase "Multi block with external signatures roundtrip" $ do
  sk <- generateSecretKey
  eSk <- generateSecretKey
  let pk = toPublic sk
      content = "content"
  token <- signToken content sk
  attenuated <- appendSigned token eSk "block1"
  let res = verifyToken attenuated pk
  res @?= True

invalidExternalSig :: TestTree
invalidExternalSig = testCase "Invalid external signature" $ do
  sk <- generateSecretKey
  eSk <- generateSecretKey
  let pk = toPublic sk
      ePk = toPublic eSk
      content = "content"
  token <- signToken content sk
  attenuated <- appendSigned token eSk "block1"
  let bogusSignature = sign eSk ePk ("yolo yolo" :: ByteString)
      replaceExternalSig :: SignedBlock -> SignedBlock
      replaceExternalSig (p, s, _pk, Just (_, _ePk)) = (p, s, pk, Just (bogusSignature, ePk))
      replaceExternalSig sb = sb
      tamper :: Blocks -> Blocks
      tamper = fmap replaceExternalSig
      tampered = alterPayload tamper attenuated
  let res = verifyToken tampered pk
  res @?= False
