{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}

module Platform.HTTP
  (
    main
  ) where

import           ClassyPrelude
import qualified Web.Scotty as W
import           Data.Aeson (object, (.=))

main :: IO ()
main = W.scotty 3000 $ do
  W.get "/" $ do
    W.html "A combination bus hub and library project planned for Pahoa is on track to begin construction next year."
  W.get "/florida.json" $ do
    W.json $ object [
                      "top news" .= ("Hurricane Milton weakens as it marches across central Florida" :: Text),
                      "sports" .= ("Why 49ers should watch former UH linebacker Jeff Ulbrich, Jets interim coach" :: Text)
                    ]
