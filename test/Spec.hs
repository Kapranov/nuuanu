import Test.Hspec
import Test.QuickCheck
import Test.Tasty
import Control.Exception (evaluate)

import qualified Spec.Auth.Bisque.Crypto         as BsCrypto
import qualified Spec.Auth.Bisque.Executor       as BsExecutor
import qualified Spec.Auth.Bisque.Parser         as BsParser
import qualified Spec.Auth.Bisque.Quasiquoter    as BsQuasiquoter
import qualified Spec.Auth.Bisque.Roundtrip      as BsRoundtrip
import qualified Spec.Auth.Bisque.ScopedExecutor as BsScopedExecutor
import qualified Spec.Auth.Bisque.Verification   as BsVerification
import qualified Spec.Auth.Kailua.Crypto         as KaCrypto
import qualified Spec.Auth.Kailua.Executor       as KaExecutor
import qualified Spec.Auth.Kailua.Parser         as KaParser
import qualified Spec.Auth.Kailua.Quasiquoter    as KaQuasiquoter
import qualified Spec.Auth.Kailua.Roundtrip      as KaRoundtrip
import qualified Spec.Auth.Kailua.SampleReader   as KaSampleReader
import qualified Spec.Auth.Kailua.ScopedExecutor as KaScopedExecutor
import qualified Spec.Auth.Kailua.Verification   as KaVerification

main :: IO ()
main = do
  sampleReader <- KaSampleReader.getSpecs
  defaultMain $ testGroup "nuuanu"
    [ BsCrypto.specs
    , BsExecutor.specs
    , BsParser.specs
    , BsQuasiquoter.specs
    , BsRoundtrip.specs
    , BsScopedExecutor.specs
    , BsVerification.specs
    , KaCrypto.specs
    , KaExecutor.specs
    , KaParser.specs
    , KaQuasiquoter.specs
    , KaRoundtrip.specs
    , KaScopedExecutor.specs
    , KaVerification.specs
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
