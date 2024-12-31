{-# LANGUAGE DataKinds          #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleInstances  #-}
{-# LANGUAGE KindSignatures     #-}
{-# LANGUAGE NamedFieldPuns     #-}
{-# LANGUAGE RecordWildCards    #-}
{-|
  Module     : Auth.Bisque.Token
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
  Module defining the main bisque-related operations
-}
module Auth.Bisque.Token ( Bisque
                         , BisqueEncoding (..)
                         , BisqueProof (..)
                         , ExistingBlock
                         , Open
                         , OpenOrSealed
                         , ParseError (..)
                         , ParsedSignedBlock
                         , ParserConfig (..)
                         , Sealed
                         , Unverified
                         , Verified
                         , addBlock
                         , asOpen
                         , asSealed
                         , authority
                         , authorizeBisque
                         , authorizeBisqueWithLimits
                         , blocks
                         , checkBisqueSignatures
                         , fromOpen
                         , fromSealed
                         , getRevocationIds
                         , getVerifiedBisquePublicKey
                         , mkBisque
                         , mkBisqueWith
                         , parseBisqueUnverified
                         , parseBisqueWith
                         , proof
                         , proofCheck
                         , rootKeyId
                         , seal
                         , serializeBisque
                         , symbols
                         ) where

import Control.Monad                        (join, when)
import Data.Bifunctor                       (first)
import Data.ByteString                      (ByteString)
import qualified Data.ByteString.Base64.URL as B64
import Data.List.NonEmpty                   (NonEmpty ((:|)))
import qualified Data.List.NonEmpty         as NE
import Data.Set                             (Set)
import qualified Data.Set                   as Set
import Auth.Bisque.Crypto                   ( PublicKey
                                            , SecretKey
                                            , Signature
                                            , SignedBlock
                                            , convert
                                            , getSignatureProof
                                            , signBlock
                                            , toPublic
                                            , verifyBlocks
                                            , verifySecretProof
                                            , verifySignatureProof
                                            )
import Auth.Bisque.Datalog.AST              (Authorizer, Block)
import Auth.Bisque.Datalog.Executor         ( ExecutionError
                                            , Limits
                                            , defaultLimits
                                            )
import Auth.Bisque.Datalog.ScopedExecutor   ( AuthorizationSuccess
                                            , runAuthorizerWithLimits
                                            )
import qualified Auth.Bisque.Proto          as PB
import Auth.Bisque.ProtoBufAdapter          ( blockToPb
                                            , extractSymbols
                                            , pbToBlock
                                            , pbToProof
                                            , pbToSignedBlock
                                            , signedBlockToPb
                                            )
import Auth.Bisque.Symbols

type ExistingBlock = (ByteString, Block)
type ParsedSignedBlock = (ExistingBlock, Signature, PublicKey)

data OpenOrSealed
  = SealedProof Signature
  | OpenProof SecretKey
  deriving (Eq, Show)

newtype Open = Open SecretKey

newtype Sealed = Sealed Signature deriving stock (Eq, Show)

class BisqueProof a
  where
    toPossibleProofs :: a -> OpenOrSealed

instance BisqueProof OpenOrSealed where
  toPossibleProofs = id
instance BisqueProof Sealed where
  toPossibleProofs (Sealed sig) = SealedProof sig
instance BisqueProof Open where
  toPossibleProofs (Open sk) = OpenProof sk

newtype Verified = Verified PublicKey
  deriving stock (Eq, Show)

data Unverified = Unverified
  deriving stock (Eq, Show)

data Bisque proof check
  = Bisque
  { rootKeyId  :: Maybe Int
  , symbols    :: Symbols
  , authority  :: ParsedSignedBlock
  , blocks     :: [ParsedSignedBlock]
  , proof      :: proof
  , proofCheck :: check
  }
  deriving (Eq, Show)

fromOpen :: Bisque Open check -> Bisque OpenOrSealed check
fromOpen b@Bisque{proof = Open p } = b { proof = OpenProof p }

fromSealed :: Bisque Sealed check -> Bisque OpenOrSealed check
fromSealed b@Bisque{proof = Sealed p } = b { proof = SealedProof p }

asSealed :: Bisque OpenOrSealed check -> Maybe (Bisque Sealed check)
asSealed b@Bisque{proof} = case proof of
  SealedProof p -> Just $ b { proof = Sealed p }
  _             -> Nothing

asOpen :: Bisque OpenOrSealed check -> Maybe (Bisque Open check)
asOpen b@Bisque{proof}   = case proof of
  OpenProof p -> Just $ b { proof = Open p }
  _           -> Nothing

toParsedSignedBlock :: Block -> SignedBlock -> ParsedSignedBlock
toParsedSignedBlock block (serializedBlock, sig, pk) = ((serializedBlock, block), sig, pk)

mkBisque :: SecretKey -> Block -> IO (Bisque Open Verified)
mkBisque = mkBisqueWith Nothing

mkBisqueWith :: Maybe Int -> SecretKey -> Block -> IO (Bisque Open Verified)
mkBisqueWith rootKeyId sk authority = do
  let (authoritySymbols, authoritySerialized) = PB.encodeBlock <$> blockToPb newSymbolTable authority
  (signedBlock, nextSk) <- signBlock sk authoritySerialized
  pure Bisque { rootKeyId
               , authority = toParsedSignedBlock authority signedBlock
               , blocks = []
               , symbols = addFromBlock newSymbolTable authoritySymbols
               , proof = Open nextSk
               , proofCheck = Verified $ toPublic sk
               }

addBlock :: Block
         -> Bisque Open check
         -> IO (Bisque Open check)
addBlock block b@Bisque{..} = do
  let (blockSymbols, blockSerialized) = PB.encodeBlock <$> blockToPb symbols block
      Open p = proof
  (signedBlock, nextSk) <- signBlock p blockSerialized
  pure $ b { blocks = blocks <> [toParsedSignedBlock block signedBlock]
           , symbols = addFromBlock symbols blockSymbols
           , proof = Open nextSk
           }

seal :: Bisque Open check -> Bisque Sealed check
seal b@Bisque{..} =
  let Open sk = proof
      ((lastPayload, _), lastSig, lastPk) = NE.last $ authority :| blocks
      newProof = Sealed $ getSignatureProof (lastPayload, lastSig, lastPk) sk
   in b { proof = newProof }

serializeBisque :: BisqueProof p => Bisque p Verified -> ByteString
serializeBisque Bisque{..} =
  let proofField = case toPossibleProofs proof of
          SealedProof sig -> PB.ProofSignature $ PB.putField (convert sig)
          OpenProof   sk  -> PB.ProofSecret $ PB.putField (convert sk)
   in PB.encodeBlockList PB.Bisque
        { rootKeyId = PB.putField $ fromIntegral <$> rootKeyId
        , authority = PB.putField $ toPBSignedBlock authority
        , blocks    = PB.putField $ toPBSignedBlock <$> blocks
        , proof     = PB.putField proofField
        }

toPBSignedBlock :: ParsedSignedBlock -> PB.SignedBlock
toPBSignedBlock ((block, _), sig, pk) = signedBlockToPb (block, sig, pk)

data ParseError
  = InvalidHexEncoding
  | InvalidB64Encoding
  | InvalidProtobufSer Bool String
  | InvalidProtobuf Bool String
  | InvalidSignatures
  | InvalidProof
  | RevokedBisque
  deriving (Eq, Show)

data BisqueWrapper
  = BisqueWrapper
  { wAuthority :: SignedBlock
  , wBlocks    :: [SignedBlock]
  , wProof     :: OpenOrSealed
  , wRootKeyId :: Maybe Int
  }

parseBisqueWrapper :: ByteString -> Either ParseError BisqueWrapper
parseBisqueWrapper bs = do
  blockList <- first (InvalidProtobufSer True) $ PB.decodeBlockList bs
  let rootKeyId = fromEnum <$> PB.getField (PB.rootKeyId blockList)
  signedAuthority <- first (InvalidProtobuf True) $ pbToSignedBlock $ PB.getField $ PB.authority blockList
  signedBlocks    <- first (InvalidProtobuf True) $ traverse pbToSignedBlock $ PB.getField $ PB.blocks blockList
  proof         <- first (InvalidProtobuf True) $ pbToProof $ PB.getField $ PB.proof blockList

  pure $ BisqueWrapper
    { wAuthority = signedAuthority
    , wBlocks = signedBlocks
    , wProof  = either SealedProof
                       OpenProof
                       proof
    , wRootKeyId = rootKeyId
    , ..
    }

checkRevocation :: Applicative m
                => (Set ByteString -> m Bool)
                -> BisqueWrapper
                -> m (Either ParseError BisqueWrapper)
checkRevocation isRevoked bw@BisqueWrapper{wAuthority,wBlocks} =
  let getRevocationId (_, sig, _) = convert sig
      revocationIds = getRevocationId <$> wAuthority :| wBlocks
      keepIfNotRevoked True  = Left RevokedBisque
      keepIfNotRevoked False = Right bw
   in keepIfNotRevoked <$> isRevoked (Set.fromList $ NE.toList revocationIds)

parseBlocks :: BisqueWrapper -> Either ParseError (Symbols, NonEmpty ParsedSignedBlock)
parseBlocks BisqueWrapper{..} = do
  let toRawSignedBlock (payload, sig, pk') = do
        pbBlock <- first (InvalidProtobufSer False) $ PB.decodeBlock payload
        pure ((payload, pbBlock), sig, pk')

  rawAuthority <- toRawSignedBlock wAuthority
  rawBlocks    <- traverse toRawSignedBlock wBlocks

  let symbols = extractSymbols $ (\((_, p), _, _) -> p) <$> rawAuthority : rawBlocks

  authority <- rawSignedBlockToParsedSignedBlock symbols rawAuthority
  blocks    <- traverse (rawSignedBlockToParsedSignedBlock symbols) rawBlocks
  pure (symbols, authority :| blocks)

parseBisqueUnverified :: ByteString -> Either ParseError (Bisque OpenOrSealed Unverified)
parseBisqueUnverified bs = do
  w@BisqueWrapper{..} <- parseBisqueWrapper bs
  (symbols, authority :| blocks) <- parseBlocks w
  pure $ Bisque { rootKeyId = wRootKeyId
                 , proof = wProof
                 , proofCheck = Unverified
                 , .. }

parseBisque' :: PublicKey -> BisqueWrapper -> Either ParseError (Bisque OpenOrSealed Verified)
parseBisque' pk w@BisqueWrapper{..} = do
  let allBlocks = wAuthority :| wBlocks
  let blocksResult = verifyBlocks allBlocks pk
  let proofResult = case wProof of
        SealedProof sig -> verifySignatureProof sig (NE.last allBlocks)
        OpenProof   sk  -> verifySecretProof sk     (NE.last allBlocks)
  when (not blocksResult || not proofResult) $ Left InvalidSignatures

  (symbols, authority :| blocks) <- parseBlocks w
  pure $ Bisque { rootKeyId = wRootKeyId
                 , proof = wProof
                 , proofCheck = Verified pk
                 , .. }

checkBisqueSignatures :: BisqueProof proof
                       => (Maybe Int -> PublicKey)
                       -> Bisque proof Unverified
                       -> Either ParseError (Bisque proof Verified)
checkBisqueSignatures getPublicKey b@Bisque{..} = do
  let pk = getPublicKey rootKeyId
      toSignedBlock ((payload, _), sig, nextPk) = (payload, sig, nextPk)
      allBlocks = toSignedBlock <$> (authority :| blocks)
      blocksResult = verifyBlocks allBlocks pk
      proofResult = case toPossibleProofs proof of
        SealedProof sig -> verifySignatureProof sig (NE.last allBlocks)
        OpenProof   sk  -> verifySecretProof sk     (NE.last allBlocks)
  when (not blocksResult || not proofResult) $ Left InvalidSignatures
  pure $ b { proofCheck = Verified pk }

data BisqueEncoding
  = RawBytes
  | UrlBase64

data ParserConfig m
  = ParserConfig
  { encoding     :: BisqueEncoding
  , isRevoked    :: Set ByteString -> m Bool
  , getPublicKey :: Maybe Int -> PublicKey
  }

parseBisqueWith :: Applicative m
                 => ParserConfig m
                 -> ByteString
                 -> m (Either ParseError (Bisque OpenOrSealed Verified))
parseBisqueWith ParserConfig{..} bs =
  let input = case encoding of
        RawBytes  -> Right bs
        UrlBase64 -> first (const InvalidB64Encoding) . B64.decode $ bs
      parsedWrapper = parseBisqueWrapper =<< input
      wrapperToBisque w@BisqueWrapper{wRootKeyId} =
        let pk = getPublicKey wRootKeyId
         in (parseBisque' pk =<<) <$> checkRevocation isRevoked w
   in join <$> traverse wrapperToBisque parsedWrapper

rawSignedBlockToParsedSignedBlock :: Symbols
                                  -> ((ByteString, PB.Block), Signature, PublicKey)
                                  -> Either ParseError ParsedSignedBlock
rawSignedBlockToParsedSignedBlock s ((payload, pbBlock), sig, pk) = do
  block   <- first (InvalidProtobuf False) $ pbToBlock s pbBlock
  pure ((payload, block), sig, pk)

getRevocationIds :: Bisque proof check -> NonEmpty ByteString
getRevocationIds Bisque{authority, blocks} =
  let allBlocks = authority :| blocks
      getRevocationId (_, sig, _) = convert sig
   in getRevocationId <$> allBlocks

getVerifiedBisquePublicKey :: Bisque a Verified -> PublicKey
getVerifiedBisquePublicKey Bisque{proofCheck} =
  let Verified pk = proofCheck
   in pk

authorizeBisqueWithLimits :: Limits -> Bisque a Verified -> Authorizer -> IO (Either ExecutionError AuthorizationSuccess)
authorizeBisqueWithLimits l Bisque{..} authorizer =
  let toBlockWithRevocationId ((_, block), sig, _) = (block, convert sig)
  in runAuthorizerWithLimits l (toBlockWithRevocationId authority) (toBlockWithRevocationId <$> blocks) authorizer

authorizeBisque :: Bisque proof Verified -> Authorizer -> IO (Either ExecutionError AuthorizationSuccess)
authorizeBisque = authorizeBisqueWithLimits defaultLimits
