{-|
  Module     : Auth.Kailua.Proto
  Copyright  : updated © Oleg G.Kapranov, 2025
  License    : MIT
  Maintainer : lugatex@yahoo.com
  Haskell data structures mapping the biscuit protobuf definitions
-}
module Auth.Kailua.Proto ( Algorithm (..)
                         , BinaryKind (..)
                         , Block (..)
                         , CheckKind (..)
                         , CheckV2 (..)
                         , ExPublicKey (..)
                         , ExpressionV2 (..)
                         , ExternalSig (..)
                         , FactV2 (..)
                         , Kailua (..)
                         , Op (..)
                         , OpBinary (..)
                         , OpTernary (..)
                         , OpUnary (..)
                         , PredicateV2 (..)
                         , Proof (..)
                         , RuleV2 (..)
                         , Scope (..)
                         , ScopeType (..)
                         , SignedBlock (..)
                         , TermSet (..)
                         , TermV2 (..)
                         , TernaryKind (..)
                         , ThirdPartyBlockContents (..)
                         , ThirdPartyBlockRequest (..)
                         , UnaryKind (..)
                         , decodeBlock
                         , decodeBlockList
                         , decodeThirdPartyBlockContents
                         , decodeThirdPartyBlockRequest
                         , encodeBlock
                         , encodeBlockList
                         , encodeThirdPartyBlockContents
                         , encodeThirdPartyBlockRequest
                         , getField
                         , putField
                         ) where

import Auth.Kailua.Types    ( Algorithm (..)
                            , BinaryKind (..)
                            , Block (..)
                            , CheckKind (..)
                            , CheckV2 (..)
                            , ExPublicKey (..)
                            , ExpressionV2 (..)
                            , ExternalSig (..)
                            , FactV2 (..)
                            , Kailua (..)
                            , Op (..)
                            , OpBinary (..)
                            , OpTernary (..)
                            , OpUnary (..)
                            , PredicateV2 (..)
                            , Proof (..)
                            , RuleV2 (..)
                            , Scope (..)
                            , ScopeType (..)
                            , SignedBlock (..)
                            , TermSet (..)
                            , TermV2 (..)
                            , TernaryKind (..)
                            , ThirdPartyBlockContents (..)
                            , ThirdPartyBlockRequest (..)
                            , UnaryKind (..)
                            )
import Data.ByteString      (ByteString)
import Data.ProtocolBuffers
import Data.Serialize

decodeBlockList :: ByteString -> Either String Kailua
decodeBlockList = runGet decodeMessage

decodeBlock :: ByteString -> Either String Block
decodeBlock = runGet decodeMessage

encodeBlockList :: Kailua -> ByteString
encodeBlockList = runPut . encodeMessage

encodeBlock :: Block -> ByteString
encodeBlock = runPut . encodeMessage

encodeThirdPartyBlockRequest :: ThirdPartyBlockRequest -> ByteString
encodeThirdPartyBlockRequest = runPut . encodeMessage

encodeThirdPartyBlockContents :: ThirdPartyBlockContents -> ByteString
encodeThirdPartyBlockContents = runPut . encodeMessage

decodeThirdPartyBlockRequest :: ByteString -> Either String ThirdPartyBlockRequest
decodeThirdPartyBlockRequest = runGet decodeMessage

decodeThirdPartyBlockContents :: ByteString -> Either String ThirdPartyBlockContents
decodeThirdPartyBlockContents = runGet decodeMessage
