{-# LANGUAGE CPP #-}
{-|
  Module     : Auth.Bisque.Utils
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
-}
module Auth.Bisque.Utils ( decodeHex
                         , encodeHex
                         , encodeHex'
                         , maybeToRight
                         ) where
#if MIN_VERSION_base16(1,0,0)
import qualified Data.Base16.Types      as Hex
#endif
import Data.ByteString                  (ByteString)
import qualified Data.ByteString.Base16 as Hex
import Data.Text                        (Text)

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

decodeHex :: ByteString -> Either Text ByteString
#if MIN_VERSION_base16(1,0,0)
decodeHex = Hex.decodeBase16Untyped
#else
decodeHex = Hex.decodeBase16
#endif

maybeToRight :: b -> Maybe a -> Either b a
maybeToRight b = maybe (Left b) Right
