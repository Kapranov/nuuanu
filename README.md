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
        2024stack exec -- nuuanu-exe --port $PORT

### 10 Oct 2024 by Oleg G.Kapranov
