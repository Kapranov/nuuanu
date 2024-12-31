{-# LANGUAGE QuasiQuotes #-}
import Criterion.Main
import Auth.Bisque

buildToken :: SecretKey -> IO (Bisque Open Verified)
buildToken sk = do
  mkBisque sk [block|user_id("user_1234");|]

main :: IO ()
main = do
  sk <- newSecret
  bisque <- buildToken sk
  let pk = toPublic sk
  let bisqueBs = serialize bisque
  defaultMain [
    bgroup "bisque" [ bench "mkBisque"  $ whnfIO (buildToken sk)
                    , bench "parse"     $ whnf (parse pk) bisqueBs
                    , bench "serialize" $ whnf serialize bisque
                    , bench "verify"    $ whnfIO (authorizeBisque bisque [authorizer|allow if user_id("user_1234");|])
                    ]
    ]
