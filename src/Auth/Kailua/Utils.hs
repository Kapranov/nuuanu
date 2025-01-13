{-# LANGUAGE CPP #-}
-- |
--  Module     : Auth.Kailua.Utils
--  Copyright  : updated © Oleg G.Kapranov, 2025
--  License    : MIT
--  Maintainer : lugatex@yahoo.com

module Auth.Kailua.Utils ( allM
                         , anyM
                         , decodeHex
                         , encodeHex
                         , encodeHex'
                         , foldMapM
                         , mapMaybeM
                         , maybeToRight
                         , rightToMaybe
                         , setFilterM
                         ) where

#if MIN_VERSION_base16(1,0,0)
import qualified Data.Base16.Types      as Hex
#endif
import           Data.Bool              (bool)
import           Data.ByteString        (ByteString)
import qualified Data.ByteString.Base16 as Hex
import           Data.Maybe             (maybeToList)
import           Data.Monoid            (All (..), Any (..))
import           Data.Set               (Set)
import qualified Data.Set               as Set
import           Data.Text              (Text)

allM :: (Foldable t, Monad m) => (a -> m Bool) -> t a -> m Bool
allM f = fmap getAll . foldMapM (fmap All . f)

anyM :: (Foldable t, Monad m) => (a -> m Bool) -> t a -> m Bool
anyM f = fmap getAny . foldMapM (fmap Any . f)

decodeHex :: ByteString -> Either Text ByteString
#if MIN_VERSION_base16(1,0,0)
decodeHex = Hex.decodeBase16Untyped
#else
decodeHex = Hex.decodeBase16
#endif

encodeHex :: ByteString -> Text
#if MIN_VERSION_base16(1,0,0)
encodeHex = Hex.extractBase16 . Hex.encodeBase16
#else
encodeHex = Hex.encodeBase16
#endif

encodeHex' :: ByteString -> ByteString
#if MIN_VERSION_base16(1,0,0)
encodeHex' = Hex.extractBase16 . Hex.encodeBase16'
#else
encodeHex' = Hex.encodeBase16'
#endif

foldMapM :: (Monoid b, Monad m, Foldable f) => (a -> m b) -> f a -> m b
foldMapM f xs = foldr step return xs mempty
  where
    step x r z = f x >>= \y -> r $! z `mappend` y
{-# INLINE foldMapM #-}

mapMaybeM :: (Monad m) => (a -> m (Maybe b)) -> [a] -> m [b]
mapMaybeM f = foldMapM (fmap maybeToList . f)

maybeToRight :: b -> Maybe a -> Either b a
maybeToRight b = maybe (Left b) Right

rightToMaybe :: Either b a -> Maybe a
rightToMaybe = either (const Nothing) Just

setFilterM :: (Ord a, Monad m) => (a -> m Bool) -> Set a -> m (Set a)
setFilterM p = foldMapM (\a -> bool mempty (Set.singleton a) <$> p a)
