import Test.Hspec
import Test.QuickCheck
import Test.Tasty
import Control.Exception (evaluate)
import qualified Spec.Auth.Kailua.Crypto as Crypto

main :: IO ()
main = do
  defaultMain $ testGroup "nuuanu"
    [Crypto.specs]
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
