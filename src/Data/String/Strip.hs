module Data.String.Strip (main, strip) where

import Data.Char

main :: IO ()
main = putStrLn "No errors!"

strip :: String -> String
strip = dropWhile isSpace . reverse . dropWhile isSpace . reverse
