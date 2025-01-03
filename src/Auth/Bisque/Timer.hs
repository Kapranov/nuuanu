{-|
  Module     : Auth.Bisque.Timer
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
  Helper function making sure an IO action runs in an alloted time
-}
module Auth.Bisque.Timer (timer) where

import Control.Concurrent       (threadDelay)
import Control.Concurrent.Async (race)

timer :: Int -> IO a -> IO (Maybe a)
timer timeout job = do
  let watchDog = threadDelay timeout
  result <- race watchDog job
  pure $ case result of
           Left _  -> Nothing
           Right a -> Just a
