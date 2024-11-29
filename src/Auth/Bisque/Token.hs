{-# LANGUAGE DerivingStrategies #-}
module Auth.Bisque.Token ( Open
                         , Verified
                         ) where

import           Data.ByteString                    (ByteString)
import           Auth.Bisque.Datalog.AST            (Block)
import           Auth.Bisque.Crypto                 ( MyPublicKey
                                                    , MySignature
                                                    , MySecretKey
                                                    )

newtype Verified = Verified MyPublicKey deriving stock (Eq, Show)
newtype Open = Open MySecretKey deriving stock (Eq, Show)

type ExistingBlock = (ByteString, Block)
type ParsedSignedBlock = (ExistingBlock, MySignature, MyPublicKey, Maybe (MySignature, MyPublicKey))
