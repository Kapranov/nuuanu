{-# LANGUAGE CPP #-}
module Auth.Bisque.Utils (decodeHex, encodeHex') where
#if MIN_VERSION_base16(1,0,0)
import qualified Data.Base16.Types      as Hex
#endif
import           Data.ByteString        (ByteString)
import qualified Data.ByteString.Base16 as Hex
import           Data.Text              (Text)

decodeHex :: ByteString -> Either Text ByteString
#if MIN_VERSION_base16(1,0,0)
decodeHex = Hex.decodeBase16Untyped
#else
decodeHex = Hex.decodeBase16
#endif
encodeHex' :: ByteString -> ByteString
#if MIN_VERSION_base16(1,0,0)
encodeHex' = Hex.extractBase16 . Hex.encodeBase16'
#else
encodeHex' = Hex.encodeBase16'
#endif
