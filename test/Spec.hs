import Test.Hspec
import Test.QuickCheck
import Test.Tasty
import Control.Exception (evaluate)

import qualified Spec.Auth.Kailua.Crypto         as Crypto
import qualified Spec.Auth.Kailua.Executor       as Executor
import qualified Spec.Auth.Kailua.Parser         as Parser
import qualified Spec.Auth.Kailua.Quasiquoter    as Quasiquoter
import qualified Spec.Auth.Kailua.Roundtrip      as Roundtrip
import qualified Spec.Auth.Kailua.SampleReader   as SampleReader
import qualified Spec.Auth.Kailua.ScopedExecutor as ScopedExecutor
import qualified Spec.Auth.Kailua.Verification   as Verification

main :: IO ()
main = do
  sampleReader <- SampleReader.getSpecs
  defaultMain $ testGroup "nuuanu"
    [ Crypto.specs
    , Executor.specs
    , Parser.specs
    , Quasiquoter.specs
    , Roundtrip.specs
    , Verification.specs
    , ScopedExecutor.specs
    , sampleReader
    ]
  hspec spec

spec :: Spec
spec = do
  describe "Prelude.head" $ do
    it "returns the first element of a list" $ do
      head [23 ..] `shouldBe` (23 :: Int)
    it "returns the first element of an *arbitrary* list" $
      property $ \x xs -> head (x:xs) == (x :: Int)
    it "throws an exception if used with an empty list" $ do
      evaluate (head []) `shouldThrow` anyException
