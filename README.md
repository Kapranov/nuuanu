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
        $ doctest src/Data/Algebraic/Custom.hs

Examples
---------

** Putting the example together:

* Ensure your working directory is `$ROOT`.
* Open `src/b/ModuleB.hs` in your text editor
* The application compiles without any issues by running `ghc -i=src/a -i=src/b src/ModuleB.hs` in `$ROOT`.
* Similarly, running ghcide in `$ROOT` also does not produce any type errors.

### 10 Oct 2024 by Oleg G.Kapranov
