# Developing backend JSON API server

Build
------

        $ stack new nuuanu new-template --verbosity debug
        $ stack build
        $ stack test
        Test suite nuuanu-test passed
        $ stack exec nuuanu-exe
        someFunc
        $ stack run
        $ export PORT=8080
        $ stack exec ghci
        > :load app/Main.hs
        $ stack exec -- nuuanu-exe --port $PORT

Allow promotion of data types to kind level
--------------------------------------------

        ghci> :set -XDataKinds
        ghci> :k Succ
        Succ :: Nat -> Nat
        ghci> :k Zero
        Zero :: Nat
        ghci> (mult four $ add two three)
        20

Tests
------

        $ stack test
        $ stack runhaskell test/Spec.hs

### 10 Oct 2024 by Oleg G.Kapranov
