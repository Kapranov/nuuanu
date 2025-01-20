{-# LANGUAGE QuasiQuotes #-}
import Criterion.Main
import Auth.Bisque as B
import Auth.Kailua as K

buildTokenB :: B.SecretKey -> IO (B.Bisque B.Open B.Verified)
buildTokenB sk = do
  B.mkBisque sk [B.block|user_id("user_1234");|]

buildTokenK :: K.SecretKey -> IO (K.Kailua K.Open K.Verified)
buildTokenK sk = do
  K.mkKailua sk [K.block|user_id("user_1234");|]

main :: IO ()
main = do
  skb <- B.newSecret
  skk <- K.newSecret
  bisque <- buildTokenB skb
  kailua <- buildTokenK skk
  let pkb = B.toPublic skb
  let pkk = K.toPublic skk
  let bisqueBs = B.serialize bisque
  let kailuaBs = K.serialize kailua
  defaultMain [
    bgroup "bisque" [ bench "mkBisque"  $ whnfIO (buildTokenB skb)
                    , bench "parse"     $ whnf (B.parse pkb) bisqueBs
                    , bench "serialize" $ whnf B.serialize bisque
                    , bench "verify"    $ whnfIO (B.authorizeBisque bisque [B.authorizer|allow if user_id("user_1234");|])
                    ],
    bgroup "kailua" [ bench "mkKailua"  $ whnfIO (buildTokenK skk)
                    , bench "parse"     $ whnf (K.parse pkk) kailuaBs
                    , bench "serialize" $ whnf K.serialize kailua
                    , bench "verify"    $ whnfIO (K.authorizeKailua kailua [K.authorizer|allow if user_id("user_1234");|])
                    ]
    ]
