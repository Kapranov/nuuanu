{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
{-|
  Module     : Auth.Bisque.Servant
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
-}
module Auth.Bisque.Servant ( RequireBisque
                           , WithAuthorizer (..)
                           , module Bisque
                           , authHandler
                           , checkBisque
                           , checkBisqueM
                           , genBisqueCtx
                           , handleBisque
                           , noAuthorizer
                           , noAuthorizer_
                           , withAuthorizer
                           , withAuthorizerM
                           , withAuthorizerM_
                           , withAuthorizer_
                           , withFallbackAuthorizer
                           , withFallbackAuthorizerM
                           , withPriorityAuthorizer
                           , withPriorityAuthorizerM
                           ) where

import Auth.Bisque                      as Bisque
import Data.Kind (Type)
import Control.Applicative              (liftA2)
import Control.Monad.Except             (MonadError, throwError)
import Control.Monad.IO.Class           (MonadIO, liftIO)
import Control.Monad.Reader             (ReaderT, lift, runReaderT)
import Data.Bifunctor                   (first)
import qualified Data.ByteString        as BS
import qualified Data.ByteString.Char8  as C8
import qualified Data.ByteString.Lazy   as LBS
import Network.Wai
import Servant                          (AuthProtect)
import Servant.Server
import Servant.Server.Experimental.Auth

type RequireBisque = AuthProtect "bisque"
type instance AuthServerData RequireBisque = Bisque OpenOrSealed Verified

data WithAuthorizer (m :: Type -> Type) (a :: Type)
  = WithAuthorizer
  { handler_    :: ReaderT (Bisque OpenOrSealed Verified) m a
  , authorizer_ :: m Authorizer
  }

withFallbackAuthorizer :: Functor m => Authorizer -> WithAuthorizer m a -> WithAuthorizer m a
withFallbackAuthorizer newV h@WithAuthorizer{authorizer_} =
  h { authorizer_ = (<> newV) <$> authorizer_ }

withFallbackAuthorizerM :: Applicative m => m Authorizer -> WithAuthorizer m a -> WithAuthorizer m a
withFallbackAuthorizerM newV h@WithAuthorizer{authorizer_} =
  h { authorizer_ = liftA2 (<>) authorizer_ newV }

withPriorityAuthorizer :: Functor m => Authorizer -> WithAuthorizer m a -> WithAuthorizer m a
withPriorityAuthorizer newV h@WithAuthorizer{authorizer_} =
     h { authorizer_ = (newV <>) <$> authorizer_ }

withPriorityAuthorizerM :: Applicative m => m Authorizer -> WithAuthorizer m a -> WithAuthorizer m a
withPriorityAuthorizerM newV h@WithAuthorizer{authorizer_} =
     h { authorizer_ = liftA2 (<>) newV authorizer_ }

withAuthorizer :: Applicative m => Authorizer -> ReaderT (Bisque OpenOrSealed Verified) m a -> WithAuthorizer m a
withAuthorizer v handler_ =
  WithAuthorizer
    { handler_
    , authorizer_ = pure v
    }

withAuthorizerM :: m Authorizer -> ReaderT (Bisque OpenOrSealed Verified) m a -> WithAuthorizer m a
withAuthorizerM authorizer_ handler_ =
  WithAuthorizer
    { handler_
    , authorizer_
    }

withAuthorizer_ :: Monad m => Authorizer -> m a -> WithAuthorizer m a
withAuthorizer_ v = withAuthorizer v . lift

withAuthorizerM_ :: Monad m => m Authorizer -> m a -> WithAuthorizer m a
withAuthorizerM_ v = withAuthorizerM v . lift

noAuthorizer :: Applicative m => ReaderT (Bisque OpenOrSealed Verified) m a -> WithAuthorizer m a
noAuthorizer = withAuthorizer mempty

noAuthorizer_ :: Monad m => m a -> WithAuthorizer m a
noAuthorizer_ = noAuthorizer . lift

extractBisque :: PublicKey -> Request -> Either String (Bisque OpenOrSealed Verified)
extractBisque pk req = do
  let note e = maybe (Left e) Right
  authHeader <- note "Missing Authorization header" . lookup "Authorization" $ requestHeaders req
  b64Token   <- note "Not a Bearer token" $ BS.stripPrefix "Bearer " authHeader
  first (const "Not a B64-encoded bisque") $ parseB64 pk b64Token

authHandler :: PublicKey -> AuthHandler Request (Bisque OpenOrSealed Verified)
authHandler publicKey = mkAuthHandler handler
  where
    authError s = err401 { errBody = LBS.fromStrict (C8.pack s) }
    orError = either (throwError . authError) pure
    handler req =
      orError $ extractBisque publicKey req

genBisqueCtx :: PublicKey -> Context '[AuthHandler Request (Bisque OpenOrSealed Verified)]
genBisqueCtx pk = authHandler pk :. EmptyContext

checkBisque :: (MonadIO m, MonadError ServerError m) => Bisque OpenOrSealed Verified -> Authorizer -> m a -> m a
checkBisque vb v h = do
  res <- liftIO $ authorizeBisque vb v
  case res of
    Left e  -> do liftIO $ print e
                  throwError $ err401 { errBody = "Bisque failed checks" }
    Right _ -> h

checkBisqueM :: (MonadIO m, MonadError ServerError m) => Bisque OpenOrSealed Verified -> m Authorizer -> m a -> m a
checkBisqueM vb mv h = do
  v   <- mv
  res <- liftIO $ authorizeBisque vb v
  case res of
    Left e  -> do liftIO $ print e
                  throwError $ err401 { errBody = "Bisque failed checks" }
    Right _ -> h

handleBisque :: (MonadIO m, MonadError ServerError m) => Bisque OpenOrSealed Verified -> WithAuthorizer m a -> m a
handleBisque b WithAuthorizer{authorizer_, handler_} =
  let h = runReaderT handler_ b
  in checkBisqueM b authorizer_ h
