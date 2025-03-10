# Developing backend JSON API server

Pass environment variables into Haskell programs run via stack
---------------------------------------------------------------

By default, stack will run the build in a pure Nix build environment (or shell),
which means two important things: (1) basically no environment variable will be
forwarded from your user session to the nix-shell `[...]`.

To override this behaviour, add `pure: false` to your `stack.yaml`
or pass the `--no-nix-pure` option to the command line.

```
bash> FOOBAR=123 stack --no-nix-pure runhaskell testenv.hs
123
```

```haskell
import System.Environment
main :: IO ()
main = print =<< getEnv "FOOBAR"
```

```
bash> FOOBAR=123 stack runhaskell testenv.hs
123
```

```haskell
import System.Environment

main = do
    setEnv "FOO" "1"
    putStr "FOO:" >> (putStrLn  =<< getEnv "FOO")
    putStr "BAR:" >> (print  =<< lookupEnv "BAR")
    putStrLn ""
    mapM_ putStrLn =<< map fst `fmap` getEnvironment
```

```
bash> runhaskell environment-variables.hs
FOO:1
BAR:Nothing

MANPATH
rvm_bin_path
TERM_PROGRAM

bash> BAR=2 runhaskell environment-variables.hs
FOO:1
BAR:Just "2"
```

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
        $ export BISQUE_SECRET_KEY=""
        $ stack exec ghci
        > :load app/Main.hs
        $ stack exec -- nuuanu-exe --port $PORT

Queries through a web browser
------------------------------

- `localhost:8080` Welcome greeting
- `localhost:8080/florida.json` The sports and top news
- `localhost:8080/kokua.json` An example of a null data
- `localhost:8080/manoa.json` All users application data
- `localhost:8080/pahoa.json` The local today info
- `localhost:8080/users/5eb2a0c4-5047-4439-a6f6-aefca3a38061` Using user id as a query parameter
- `localhost:8080/hello` 404: File Not Found!

Curl to make a query to the server
-----------------------------------

```
bash> curl localhost:8080
bash> curl localhost:8080/avian.json | jq .
bash> curl localhost:8080/kokua.json | jq .
bash> curl localhost:8080/manoa.json | jq .
bash> curl localhost:8080/pahoa.json | jq .
bash> curl localhost:8080/users/baa6d0ef-d278-4b10-9636-87770f30d636 | jq .
bash> curl localhost:8080/agent
bash> curl localhost:8080/agent -v
bash> curl localhost:8080/hello
bash> curl localhost:8080/hello.txt
bash> curl localhost:8080/hello.json | jq .
bash> curl localhost:8080/oahus
bash> curl localhost:8080/oahut.txt
bash> curl localhost:8080/oahuj.json | jq .
bash> curl localhost:8080/reefs?name=Aloha
```

Benchmarks
----------------

```bash
[console] # cd benchmarks/
[console] # ./Main
benchmarking bisque/mkBisque
time                 20.87 μs   (19.34 μs .. 22.63 μs)
                     0.957 R²   (0.936 R² .. 0.977 R²)
mean                 21.42 μs   (20.14 μs .. 22.69 μs)
std dev              3.946 μs   (3.350 μs .. 4.726 μs)
variance introduced by outliers: 95% (severely inflated)

benchmarking bisque/parse
time                 77.14 μs   (76.01 μs .. 79.17 μs)
                     0.993 R²   (0.987 R² .. 0.997 R²)
mean                 76.69 μs   (74.86 μs .. 79.26 μs)
std dev              7.003 μs   (4.769 μs .. 9.367 μs)
variance introduced by outliers: 79% (severely inflated)

benchmarking bisque/serialize
time                 3.209 μs   (3.056 μs .. 3.373 μs)
                     0.982 R²   (0.977 R² .. 0.988 R²)
mean                 3.184 μs   (3.075 μs .. 3.357 μs)
std dev              427.3 ns   (311.2 ns .. 586.8 ns)
variance introduced by outliers: 93% (severely inflated)

benchmarking bisque/verify
time                 3.577 μs   (3.366 μs .. 3.825 μs)
                     0.974 R²   (0.965 R² .. 0.984 R²)
mean                 3.677 μs   (3.536 μs .. 3.842 μs)
std dev              542.6 ns   (454.3 ns .. 656.8 ns)
variance introduced by outliers: 94% (severely inflated)
```

API token-based authorization system
-------------------------------------


Usage via commands:

Testing API token-based authorization system
---------------------------------------------

- `DONE` addBlock
- `DONE` authorizeBisque
- `DONE` authorizer
- `DONE` block
- `DONE` blockContext
- `DONE` fromHex
- `DONE` fromRevocationList
- `DONE` getSingleVariableValue
- `DONE` mkBisque
- `DONE` newPublic
- `DONE` newSecret
- `DONE` parse
- `DONE` parseB64
- `DONE` parsePublicKey
- `DONE` parsePublicKeyHex
- `DONE` parseSecretKey
- `DONE` parseSecretKeyHex
- `DONE` parseWith
- `DONE` query
- `DONE` queryAuthorizerFacts
- `DONE` seal
- `DONE` serialize
- `DONE` serializeB64
- `DONE` serializePublicKey
- `DONE` serializePublicKeyHex
- `DONE` serializeSecretKey
- `DONE` serializeSecretKeyHex
- `DONE` toPublic

 1. `basic token`
 2. `different root key`
 3. `invalid signature format`
 4. `random block`
 5. `invalid signature`
 6. `reordered blocks`
 7. `scoped rules`
 8. `scoped checks`
 9. `expired token`
10. `authorizer scope`
11. `authorizer authority checks`
12. `authority checks`
13. `block rules`
14. `regex_constraint`
15. `multi queries checks`
16. `check head name should be independent from fact names`
17. `test expression syntax and all available operations`
18. `invalid block rule with unbound_variables`
19. `invalid block rule generating an #authority or #ambient symbol with a variable`
20. `sealed token`
21. `parsing`
22. `default_symbols`
23. `execution scope`
24. `third party`
25. `block rules`
26. `public keys interning`
27. `integer wraparound`
28. `test expression syntax and all available operations (v4 blocks)`

A bearer token with offline attenuation and decentralized verification
-----------------------------------------------------------------------

A bearer token that supports offline attenuation, can be verified by any system
that knows the root public key, and provides  a flexible authorization language
based on logic programming.  It is serialized as Protocol Buffers, and designed
to be small enough for storage in HTTP cookies.

- Datalog: a declarative logic language that works on facts defining data
  relationship, rules creating more facts if conditions are met, and queries
  to test such conditions
- check: a restriction on the kind of operation that can be performed with
  the token that contains it, represented as a datalog query. For the operation
  to be valid, all of the checks defined in the token and the authorizer must
  succeed
- allow/deny policies: a list of datalog queries that are tested in a sequence
  until one of them matches. They can only be defined in the authorizer
- block: a list of datalog facts, rules and checks.
  The first block is the authority block, used to define the basic rights of a
  token
- Verified: a completely parsed bisque, whose signatures and final proof have
  been successfully verified
- Unverified: a completely parsed, whose signatures and final proof have not
  been verified yet. Manipulating unverified can be useful for generic tooling
  (eg inspecting without knowing its public key)
- Authorized: a completely parsed, whose signatures and final proof have been
  successfully verified and that was authorized in a given context, by running
  checks and policies.
- An authorized may carry informations about the successful authorization such
  as the allow query that matched and the facts generated in the process
- Authorizer: an authorizer may carry facts, rules, checks and policies.

The token is defined as a series of blocks. The first one, named "authority
block", contains rights given to the token holder. The following blocks contain
checks that reduce the token's scope, in the form of logic queries that must
succeed. The holder of a token can at any time create a new token by adding
a block with more checks, thus restricting the rights of the new token,
but they cannot remove existing blocks without invalidating the signature.

The token is protected by public key cryptography operations: the initial
creator of a token holds a secret key, and any verifier for the token needs
only to know the corresponding public key. Any attenuation operation will
employ ephemeral key pairs that are meant to be destroyed as soon as they
are used.

There is also a sealed version of that token that prevents further attenuation.

The logic language used to design rights, checks, and operation data is a
variant of datalog that accepts expressions on some data types.

The token is structured as an append-only list of blocks, containing checks,
and describing authorization properties. As with Macaroons2, an operation
must comply with all checks in order to be allowed by the token.

Checks are written as queries defined in a flavor of Datalog that supports
expressions on some data types3, without support for negation.
This simplifies its implementation and makes the check more precise.

The Datalog program contains facts and rules, which are made of predicates over
the following types: symbol, variable, integer, string, byte array and date.

- variable
- integer
- string
- byte array
- date
- boolean
- set a deduplicated list of values of any type, except variable or set

While the token does not use a textual representation for storage, we use
one for parsing and pretty printing of Datalog elements.

A predicate has the form `Predicate(v0, v1, ..., vn)`.

A `fact` is a `predicate` that does not contain any `variable`.

A rule has the form:

```
Pr(r0, r1, ..., rk) <- P0(t0_1, t0_2, ..., t0_m1), ...,
Pn(tn_1, tn_2, ..., tn_mn), E0(v0, ..., vi), ..., Ex(vx, ..., vy)
```

The part of the left of the arrow is called the `head` and on the right,
the `body`. In a `rule`, each of the `ri` or `ti_j` terms can be of any
type.
A `rule` is safe if all of the variables in the head appear somewhere
in the body.

A `query` is a type of `rule` that has no head.

```
"facts": [
  "read(0)",
  "write(1)",
  "resource(2)",
  "operation(3)",
  "right(4)",
  "time(5)",
  "role(6)",
  "owner(7)",
  "tenant(8)",
  "namespace(9)",
  "user(10)",
  "team(11)",
  "service(12)",
  "admin(13)",
  "email(14)",
  "group(15)",
  "member(16)",
  "ip_address(17)",
  "client(18)",
  "client_ip(19)",
  "domain(20)",
  "path(21)",
  "version(22)",
  "cluster(23)",
  "node(24)",
  "hostname(25)",
  "nonce(26)",
  "query(27)"
]
```

```
"rules": [
  "operation("read") <- operation($any), $any <= $any.contains("read"), $any <= $any.contains("write")",
  "right("file1", "read") <- resource("file1"), user_id("alice"), owner("alice", "file1")",
  "right("file1", "read") <- resource("file1"), user_id("alice"), owner("alice", "file1");check if resource("file1"), operation("read"), right("file1", "read");",
  "valid_date("file1") <- time($now), resource("file1"), $now <= 2030-12-31T12:59:59Z",
  "valid_date("file1") <- time($now), resource("file1"), $now <= 1999-12-31T12:59:59Z, !["file1"].contains("file1")",
  "query(1, 2) <- query(1), query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
]
```

A `check` is a list of `query` for which the token validation will fail
if it cannot produce any fact. A single query needs to match for the fact
to succeed. If any of the cheks fails, the entire verification fails.

Since the first block defines the token's rights through facts and rules,
and later blocks can define their own facts and rules, we must ensure
the token cannot increase its rights with later blocks.

This is done through execution scopes: by default, a block's rules and
checks can only apply on facts created in the authority, in the current
block or in the authorizer. Rules, checks and policies defined in the
authorizer can only apply on facts created in the authority or in the
authorizer.

Example:

- the token contains `right("file1", "read")` in the first block
- the token holder adds a block with the fact `right("file2", "read")`
- the verifier adds:
  - `resource("file2")`
  - `operation("read")`
  - `check if resource("file1"), operation("read"), right("file1", "read")`

The verifier's check will fail because when it is evaluated, it only sees
`right("file1", "read")` from the authority block.

Checks are logic queries evaluating conditions on facts. To validate
an operation, all of a token's checks must succeed.

One block can contain one or more checks.

Their text representation is `check if`, `check all` or `reject if`
followed by the body of the query. There can be multiple queries inside
of a check, it will succeed if any of them succeeds (in the case of
`reject if`, the check will fail if any query matches).
They are separated by a or token.

- a `check if` query succeeds if it finds one set of facts that matches
  the body and expressions
- a `check all` query succeeds if all the sets of facts that match the
  body also succeed the expression.
- a `reject if` query succeeds if no set of facts matches the body and
  expressions

```
"checks": [
  "check all operation($op), allowed_operations($allowed), $allowed.contains($op)",
  "check if !false && true",
  "check if !false",
  "check if "aaabde" == "aaa" + "b" + "de"",
  "check if "aaabde".contains("abd")",
  "check if "aaabde".matches("a*c?.e")",
  "check if "abcD12" == "abcD12"",
  "check if "abcD12".length() == 6",
  "check if "hello world".starts_with("hello") && "hello world".ends_with("world")",
  "check if "é".length() == 2",
  "check if (true || false) && true",
  "check if 1 != 3",
  "check if 1 + 2 * 3 - 4 / 2 == 5",
  "check if 1 < 2",
  "check if 1 <= 1",
  "check if 1 <= 2",
  "check if 1 | 2 ^ 3 == 0",
  "check if 2 > 1",
  "check if 2 >= 2",
  "check if 2019-12-04T09:46:41Z < 2020-12-04T09:46:41Z",
  "check if 2019-12-04T09:46:41Z <= 2020-12-04T09:46:41Z",
  "check if 2020-12-04T09:46:41Z == 2020-12-04T09:46:41Z",
  "check if 2020-12-04T09:46:41Z > 2019-12-04T09:46:41Z",
  "check if 2020-12-04T09:46:41Z >= 2019-12-04T09:46:41Z",
  "check if 2022-12-04T09:46:41Z != 2020-12-04T09:46:41Z",
  "check if 3 == 3",
  "check if ["abc", "def"].contains("abc")",
  "check if [1, 2, 3].intersection([1, 2]).contains(1)",
  "check if [1, 2, 3].intersection([1, 2]).length() == 2",
  "check if [1, 2] == [1, 2]",
  "check if [1, 2].contains(2)",
  "check if [1, 2].contains([2])",
  "check if [1, 2].intersection([2, 3]) == [2]",
  "check if [1, 2].union([2, 3]) == [1, 2, 3]",
  "check if [1, 4] != [1, 2]",
  "check if [2019-12-04T09:46:41Z, 2020-12-04T09:46:41Z].contains(2020-12-04T09:46:41Z)",
  "check if [false, true].contains(true)",
  "check if [hex:12ab, hex:34de].contains(hex:34de)",
  "check if "abcD12x" != "abcD12"",
  "check if false == false",
  "check if false || true",
  "check if hex:12ab == hex:12ab",
  "check if hex:12abcd != hex:12ab",
  "check if must_be_present("hello") or must_be_present("bye")",
  "check if query(1) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
  "check if query(1, 2) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189, ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
  "check if query(2) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
  "check if query(2), query(3) trusting ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463",
  "check if resource("file1")",
  "check if resource("hello")",
  "check if resource($0),operation("read"),right($0,"read")",
  "check if time($time), $time <= 2018-12-20T00:00:00Z",
  "check if true == true",
  "check if true trusting previous, ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
  "check if true || -9223372036854775808 - 1 != 0",
  "check if true || 10000000000 * 10000000000 != 0",
  "check if true || 9223372036854775807 + 1 != 0",
  "check if true"
  ]
```

The token defines some scopes for facts and rules. The `authority` scope is defined
in the first block of the token. It provides a set of facts and rules indicating
the starting rights of the token. `authority` facts can only be defined by authority
rules.
The `ambient` scope is provided by the verifier. It contains facts corresponding to
the query, like which resource we try to access, with which operation (read, write,
etc), the current time, the source IP, etc. `ambient` facts can only be defined by
the verifier.
The `local` scope contains facts specific to one block of the token. Between each
block evaluation, we do not keep the `local` facts, instead restarting from the
`authority` and `ambient` facts. Each block can contain caveats, which are `queries`
that must all succeed for the token to be valid. Additionally, the verifier can have
its own set of queries that must succeed to validate the token.

This first token defines a list of authority facts giving `read` and `write`
rights on `file1`, `read` on `file2`. The first check ensures that the operation
is `read` (and will not allow any other `operation` fact), and then that we have
the `read` right over the resource.
The second check ensures that the resource is either `file1` or `file2`.
The third check ensures that the resource is not `file1`.

```
authority:
  right("file1", "read");
  right("file2", "read");
  right("file1", "write");
----------
Block 1:
check if
  resource("file1"),
  operation("read"),
  right("file1", "read")
----------
Block 2:
check if
  resource("file1")
  or resource("file2")
----------
Block 3:
reject if
  resource("file1")
```

Queries API token-based authorization system
---------------------------------------------

HexKey - `rootPrivateKey` `99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61`
HexKey - `rootPublicKey`  `1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284`
RawKey - `rootPrivateKey` `\153\232{\SO\145XS\RS\238\181\ETX\255\NAK&n+#\194\162P{\DC3\140\157\ESC\US*\180X\223-a`
RawKey - `rootPublicKey`  `\DLEU\199P\177\161PY7\175\NAK7\198&\186\&2c\153\\3\166GX\170\175\177'[\ETX\DC2\226\132`

### BEGIN

```
λ :load src/Platform/JWT.hs

λ genKeys
Generating a new random keypair
"Private key: 99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61"
"Public  key: 1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284"

λ sk <- newSecret
λ :t sk
sk :: SecretKey

λ pk = toPublic sk
λ :t pk
pk :: PublicKey

λ new_pk <- newPublic
PublicKey "\DLEU\199P\177\161PY7\175\NAK7\198&\186\&2c\153\\3\166GX\170\175\177'[\ETX\DC2\226\132"
λ :t new_pk
new_pk :: PublicKey

λ value = Text.pack ("1234")
λ new_value = Text.pack ("123456789")
λ now <- getCurrentTime
λ ttl = addUTCTime 36000 now

λ token <- buildToken sk value
λ :t token
token :: Bisque Open Verified

λ myCheck value token
True

λ myCheck new_value token
False

λ token_add_blocked <- addTTL ttl token
λ :t token_add_blocked
token_add_blocked :: Bisque Open Verified

λ myCheck value token_add_blocked
True

λ new_ttl = addUTCTime 360 now
λ token_add_blocked <- addTTL new_ttl token
λ myCheck value token_add_blocked
False

λ token_lock = sealBisque token
λ :t token_lock
token_lock :: Bisque Sealed Verified

λ checkBisque token value
"1234"

λ checkBisque token new_value
"msg#1 The user ID you entered does not exist"

λ token_enc <- encodeBisque sk value ttl
λ :t token_enc
token_enc :: ByteString

λ token_enc64 <- encodeBisque64 sk value ttl
λ :t token_enc64
token_enc64 :: ByteString

λ verification pk token_enc value
True
λ verification64 pk token_enc64 value
True

λ verification pk token_enc new_value
ResultError (NoPoliciesMatched [])
False
λ verification64 pk token_enc64 new_value
ResultError (NoPoliciesMatched [])
False

λ parseBisque pk token_enc
True
λ parseBisque64 pk token_enc64
True

λ revocationIds = toList $ getRevocationIds token

λ pullRevocationIds token
["fb58f5b7d5a282056042cfffe6b72d82e322be229eb2585301cb42f09c32ccca64209ea1b4e547a69c83908a093df857ab2623762338c624bd0570b71373f50f"]

λ parseBisque64' pk token_enc64 revocationIds
True
λ new_token_enc64 <- encodeBisque64 sk value new_ttl
λ parseBisque64' pk new_token_enc64 revocationIds
False
```
### END

1. Create a root key (keypair - private/public keys)

- Hex keys

```haskell
λ :load src/Platform/JWT.hs

λ genKeys
Generating a new random keypair
"Private key: 99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61"
"Public  key: 1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284"
```

- RawBytes keys


```haskell
"Private key: \153\232{\SO\145XS\RS\238\181\ETX\255\NAK&n+#\194\162P{\DC3\140\157\ESC\US*\180X\223-a"
"Public  key: \DLEU\199P\177\161PY7\175\NAK7\198&\186\&2c\153\\3\166GX\170\175\177'[\ETX\DC2\226\132"
```

2. Create a private key/public key seperated with serialize/parse

- Only RawBytes keys for SecretKey

```haskell
λ sk <- newSecret
λ sk_raw = serializeSecretKey sk
"\153\232{\SO\145XS\RS\238\181\ETX\255\NAK&n+#\194\162P{\DC3\140\157\ESC\US*\180X\223-a"
```

- Only RawBytes keys from String for SecretKey

```
λ import Data.ByteString.Char8

λ str = "\153\232{\SO\145XS\RS\238\181\ETX\255\NAK&n+#\194\162P{\DC3\140\157\ESC\US*\180X\223-a"
λ Just sk = parseSecretKey $ Data.ByteString.Char8.pack str
λ sk_raw = serializeSecretKey sk
"\153\232{\SO\145XS\RS\238\181\ETX\255\NAK&n+#\194\162P{\DC3\140\157\ESC\US*\180X\223-a"
```

- Only Hex keys for SecretKey

```haskell
λ import Data.Text.Encoding (encodeUtf8)

λ Just sk_new = parseSecretKeyHex $ encodeUtf8 $ serializeSecretKeyHex sk
λ sk == sk_new
True
λ sk_hex = erializeSecretKeyHex sk
"99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61"
```

- Only Hex keys from String for SecretKey

```haskell
λ import Data.Text.Encoding (encodeUtf8)

λ str = "99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61"
λ Just sk_new = parseSecretKeyHex $ encodeUtf8 $ Text.pack str
λ sk == sk_new
True
λ sk_hex = encodeUtf8 $ Text.pack str
"99e87b0e9158531eeeb503ff15266e2b23c2a2507b138c9d1b1f2ab458df2d61" 
```

- Only RawBytes keys for PublicKey

```haskell
λ pk <- toPublic <$> return sk
λ parsePublicKey (serializePublicKey pk) == Just pk
True
λ pk_raw = serializePublicKey pk
"\DLEU\199P\177\161PY7\175\NAK7\198&\186\&2c\153\\3\166GX\170\175\177'[\ETX\DC2\226\132"
```

- Only RawBytes keys from String for PublicKey

```haskell
λ import Data.ByteString.Char8

λ str = "\DLEU\199P\177\161PY7\175\NAK7\198&\186\&2c\153\\3\166GX\170\175\177'[\ETX\DC2\226\132"
λ Just pk = parsePublicKey $ Data.ByteString.Char8.pack str
PublicKey "\DLEU\199P\177\161PY7\175\NAK7\198&\186\&2c\153\\3\166GX\170\175\177'[\ETX\DC2\226\132"
λ parsePublicKey (serializePublicKey pk) == Just pk
True
λ pk_raw = Data.ByteString.Char8.pack str
"\DLEU\199P\177\161PY7\175\NAK7\198&\186\&2c\153\\3\166GX\170\175\177'[\ETX\DC2\226\132"
```

- Only Hex keys for PublicKey

```haskell
λ pk <- toPublic <$> return sk
λ parsePublicKeyHex (encodeUtf8 $ serializePublicKeyHex pk) == Just pk
True
λ pk_hex = serializePublicKeyHex pk
"1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284"
```

- Only Hex keys from String for PublicKey

```haskell
λ import Data.Text.Encoding (encodeUtf8)

λ str = "1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284"
λ Just pk = parsePublicKeyHex $ encodeUtf8 $ Text.pack str
PublicKey "\DLEU\199P\177\161PY7\175\NAK7\198&\186\&2c\153\\3\166GX\170\175\177'[\ETX\DC2\226\132"
λ pk_hex = encodeUtf8 $ Text.pack str
"1055c750b1a1505937af1537c626ba3263995c33a64758aaafb1275b0312e284"
```

3. Create a token

```haskell
λ token <- myBisque sk
λ :t token
token :: Bisque Open Verified

λ token_raw = serialize token
λ :t token_raw
token_raw :: ByteString
λ token_raw
"\DC2\141\SOH\n#\n\EOT1234\CAN\ETX\"\t\n\a\b\n\DC2\ETX\CAN\128\b2\SO\n\f\n\STX\b\ESC\DC2\ACK\b\ETX\DC2\STX\CAN\NUL\DC2$\b\NUL\DC2 4/JE\t\203%\210S\187\f\224\165\130RP\254\253\144\149\251\DC4\131\NAK\150\164P\131\CAN\235-\SI\SUB@\241\185\232\229\t\216\DELW\175'p\236~\251\f\DC3r\162\236\224\DC3\DC1\DLE\DC2\RS\197\255\156ZK\151\210\161'\138@\245V\144\210\179\166\ap\209\156BJ\201vi\ETXj)\237x\161{t\211wTd\f\"\"\n \183\249\218\FS\213\STX)\143\241\169\161\195wx\210\169?\222\201#\NULO$\255\SUB\226\206\GS\213\180\241\f"

λ token_url = serializeB64 token
λ :t token_url
token_url :: ByteString
λ token_url
"Eo0BCiMKBDEyMzQYAyIJCgcIChIDGIAIMg4KDAoCCBsSBggDEgIYABIkCAASIDQvSkUJyyXSU7sM4KWCUlD-_ZCV-xSDFZakUIMY6y0PGkDxuejlCdh_V68ncOx--wwTcqLs4BMREBIexf-cWkuX0qEnikD1VpDSs6YHcNGcQkrJdmkDainteKF7dNN3VGQMIiIKILf52hzVAimP8amhw3d40qk_3skjAE8k_xrizh3VtPEM"
```

- The facts for a new had created block `mkBisque sk` - `[block|user("1234");check if operation("read");|]`

- The checks for a new had created block

- The policy for a new had created block

```
"policies": [
  "allow if true",
  "deny if query(0) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189",
  "deny if query(1, 2)",
  "deny if query(3)"
]
```
- Some examples

```
"user_id("alice");owner("alice","file1")"
"owner("alice","file2")"
"right("file1","read")"
"right("file1","write")"
"right("alice","read") <- resource("file1"),user_id("alice"),owner("alice","file1")"
"right("alice","read") <- resource("file1"),user_id("alice"),owner("alice","file1");check if resource("file1"),operation("read"),right("file1","read")"

"resource("file1");allow if true"
"resource("file1");operation("read");allow if true)"
"resource("file1");operation("read");time(2020-12-21T09:23:12Z);allow if true"
"resource("file1");operation("read");check if right("file1","read"),resource("file1"),operation("read");allow if true"
"resource("file1");time(2020-12-21T09:23:12Z);allow if true"
"resource("file1");allow if true"
"resource("file123.txt");allow if true"
```

4. Create an authorize

```haskell
λ auth_token = myCheck token
λ :t auth_token
auth_token :: IO Bool
λ auth_token
True
```

- Some examples

```haskell
value = True
result <- authorizeBisque bisque [authorizer|check if right("file1", "read"); allow if true;|]
result <- authorizeBisque bisque [authorizer|time({now});operation("read"); allow if true;|]
result <- authorizeBisque bisque [authorizer|current_time()|]
result <- authorizeBisque bisque [authorizer|allow if true;|]
result <- authorizeBisque bisque [authorizer|allow if false;|]
result <- authorizeBisque bisque [authorizer|operation("write"); allow if true;|]
result <- authorizeBisque bisque [authorizer|check all fact(true), true; allow if true;|]
result <- authorizeBisque bisque [authorizer|check all fact({$value}), {$value};allow if true;|]

bisque1 <- mkBisque secret [block|check if operation("read");|]
bisque2 <- addBlock [block|operation($unbound, "read") <- operation($any1, $any2);|] bisque1

bisque1 <- mkBisque secret [block|check if operation("read");|]
bisque2 <- addBlock [block|operation("read");|] bisque1
result  <- authorizeBisque bisque [authorizer|allow if true;|]

bisque1 <- mkBisque secret [block|check if operation("read");|]
bisque2 <- addBlock [block|operation($ambient, "read") <- operation($ambient, $any);|] bisque1
result  <- authorizeBisque bisque [authorizer|operation("write"); allow if true;|]
```

5. Attenuate a token

```haskell
λ ttl <- getCurrentTime
λ :t ttl
ttl :: UTCTime
λ ttl
2024-12-24 11:44:51.489297439 UTC
λ attenuate_token = addTTL ttl token
λ :t attenuate_token
attenuate_token :: IO (Bisque Open Verified)
```

6. Seal a token

```haskell
λ seal_token = sealBisque token
λ :t seal_token
seal_token :: Bisque Sealed Verified
λ seal_token
Bisque {rootKeyId = Nothing, symbols = Symbols {getSymbols = fromList [(0,"read"),(1,"write"),(2,"resource"),(3,"operation"),(4,"right"),(5,"time"),(6,"role"),(7,"owner"),(8,"tenant"),(9,"namespace"),(10,"user"),(11,"team"),(12,"service"),(13,"admin"),(14,"email"),(15,"group"),(16,"member"),(17,"ip_address"),(18,"client"),(19,"client_ip"),(20,"domain"),(21,"path"),(22,"version"),(23,"cluster"),(24,"node"),(25,"hostname"),(26,"nonce"),(27,"query"),(1024,"1234")]}, authority = (("\n\EOT1234\CAN\ETX\"\t\n\a\b\n\DC2\ETX\CAN\128\b2\SO\n\f\n\STX\b\ESC\DC2\ACK\b\ETX\DC2\STX\CAN\NUL",user("1234");
check if operation("read")),Signature "u\252\138\CAN\223\142\169\143\240\249\196\\V\130g\208\157U\139\STX\147O\ACK\GS%\r\176\222\253\226\192'\153\166ef\166\171\250\&2i\222\147\172\SOHg\238\FS\242\STXO\248\201G\171\253\211\184\153\145\b\141\146\t",PublicKey "W\252\139\&3\\X\133I\144D\214\169\248\179\178K\192G\FS\187v\183,\DC1\153#'5\197Q\203\DEL"), blocks = [], proof = Sealed (Signature "c\164\n\222\&3\NUL\ESC\208\SI\171sk\150Z\214\234\&7\225\139\176;\SYN\133\203\217\150\t\209\177\&0Hk\CAN(h\152\n\191\NUL\206\194\220\179\226\161\DC4AT(z\a\247- \153P_\135is\193\180L\NUL"), proofCheck = Verified (PublicKey "\144\239)\202\vx\165;\STXZ7 \132\142\146)V\195\235c\174\156\&1q\"\137{\202\143\149=\236")}
```

7. Reject revoked tokens

```haskell
λ token_url <- serialize token
λ token_url64 <- serializeB64 token64
λ token_url   <- encodeBisque sk
λ token_url64 <- encodeBisque64 sk
λ verification pk token_url
λ verification64 pk token_url64
ResultError (NoPoliciesMatched [[QueryItem {qBody = [Predicate {name = "operation", terms = [LString "read"]}], qExpressions = [], qScope = Nothing}]])
False
λ parseBisque pk token_url
λ parseBisque64 pk token_url64
λ
λ
```

8. Query data from the authorizer

```haskell
```

9. Inspect a token

```haskell
λ checkBisque token
"Something wrong!"
λ parseBisque pk token_url
```

- allow decentralized verification through public key cryptography
- allow offline attenuation where, from each token, a new one with narrower rights can be generated
- create strong security policy enforcement based on a logic language

A set of building blocks for your authorization layer. By making a
coherent experience from the authorization token up to the tools
to write policies, it spares you the time spent binding together
token scopes, authorization servers, and making sure authorization
policies execute correctly in every service.

Actions to create, attenuate, inspect and authorize tokens,
an online playground for Datalog policies.

To sum up, the tools for cross platform authorization system:

- an authorization token, verified by public key cryptography, that supports offline attenuation
- a logic language based on Datalog to write authorization policies
- a server side library, available for to write authorizers in your applications

One of those building blocks is an authorization token that is signed
with public key cryptography (like JWT), so that any service knowing
the public key can verify the token. The token can be transported along
with a request, in a cookie, authorization header, or any other mean.
It can be stored as binary data, or base64 encoded. It is designed
to be small enough for use in most protocols, and fast to verify to keep
a low overhead in authorization.

The token holds cryptographically signed data indicating the holder's
basic rights, and additional constraints on the request. As an example,
the token could define its use for read-only operations, or from a specific
IP address.

Here is what a token looks like: the left-hand side shows you the encoded,
while the right-hand side shows its contents. The first block (called the
authority block) gives us what the token grants access to. The other two
blocks restrict how the token can be used. Only the authority block can be
created by the token emitter, while the other blocks can be freely added
by intermediate parties (offline attenuation).

- `Encoded token`
  - `En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiAs2CFWr5WyHHWEiMhTXxVNw4gP7PlADPaGfr_AQk9WohpA6LZTjFfFhcFQrMsp2O7bOI9BOzP-jIE5PGhha62HDfX4t5FLQivX5rUhH5iTv2c-rd0kDSazrww4cD1UCeytDSIiCiCfMgpVPOuqq371l1wHVhCXoIscKW-wrwiKN80vR_Rfzg==`
- `Decoded token`
  - `Authority block`
    `Revocation id: e8b6538c57c585c150accb29d8eedb388f413b33fe8c81393c68616bad870df5f8b7914b422bd7e6b5211f9893bf673eaddd240d26b3af0c38703d5409ecad0d`
  - `Signed by: n/a`
    - `user("1234");`

Policy language:

Authorization policies are written in a logic language derived from Datalog.
Logic languages are well suited for authorization, because they can represent
complex relations between elements (like roles, groups, hierarchies)
concisely, and efficiently explore and combine multiple rules, authorization
rules can be provided by the authorizer's side, but also by the token. While
the token can carry data, it can also contain "checks", conditions that the
request must fulfill to be accepted.
This is the main mechanism for attenuation: take an existing token, add a
check for the current date (expiration) or the operation (restrict to read only).

Authorization policy example `Authorizer`:

```
// We receive a request to read "admin.doc"
// The request contains a token with the following content
user("1234"); // the user is identified as "1234"
check if operation("read"); // the token is restricted to read-only operations
// The authorizer loads facts representing the request
resource("admin.doc");
operation("read");
// The authorizer loads the user's rights
right("1234", "admin.doc", "read");
right("1234", "admin.doc", "write");
// Finally, the authorizer tests policies
// by looking for a set of facts matching them
allow if
user($user_id),
resource($res),
operation($op),
right($user_id, $res, $op);
```

Result and Success Facts

```
operation("read");

resource("admin.doc");

right("1234","admin.doc","read");
right("1234","admin.doc","write");

user("1234");
```

Requires two things:

- a private key that will allow receiving parties to trust the contents
- an authority block carrying information (and possibly restrictions)

Creating a private key:

```
❯ bisque keypair
Generating a new random keypair
Private key: 473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97
Public key: 41e77e842e5c952a29233992dc8ebbedd2d83291a89bb0eec34457e723a69526
```

The private key is used to generate token, while the public key can be
distributed to all services who will use tokens to authorize requests.


Creating a token:

The most important part is its authority block. It contains data that is
signed with the private key, and that can be trusted by receiving parties.
The authority block is declared in datalog. Datalog is a declarative logic
language that is a subset of Prolog. A Datalog program contains "facts",
which represent data, and "rules", which can generate new facts from
existing ones.

We will create a token that identifies its carrier as a user whose user id
is "1234". To do so, we will create a file named authority.datalog, with
the following contents: `user("1234");`

This is a datalog fact: the fact name is `user`, and it has a single
attribute (`"1234"`). Facts can have several attributes, of various types
(ints, strings, booleans, byte arrays, dates, sets).

Now we have a private key and an authority block, we can generate:

```
❯ bisque generate --private-key 473b5189232f3f597b5c2f3f9b0d5e28b1ee4e7cce67ec6b7fbf5984157a6b97 authority.bisque-datalog
En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBw-OHV3egI0IVjiC1vdB7WZ__t0FCvB2s-81PexdwuqxpAolMr9XDP7T44qgdXxtumc2P3O93pCHaGSuBUs3_f8nsQJ7NU6PdkujZIMStzEJ36CDnxawSZjUAKoTO-a1cCDSIiCiBPsG53WHcpxeydjSpFYNYnvPAeM1tVBvOEG9SQgMrzbw==
```


You can inspect the generated:

```
❯ bisque inspect -
Please input a base64-encoded bisque, followed by <enter> and ^D
En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBw-OHV3egI0IVjiC1vdB7WZ__t0FCvB2s-81PexdwuqxpAolMr9XDP7T44qgdXxtumc2P3O93pCHaGSuBUs3_f8nsQJ7NU6PdkujZIMStzEJ36CDnxawSZjUAKoTO-a1cCDSIiCiBPsG53WHcpxeydjSpFYNYnvPAeM1tVBvOEG9SQgMrzbw==
Authority block:
== Datalog ==
user("1234");

== Revocation id ==
a2532bf570cfed3e38aa0757c6dba67363f73bdde90876864ae054b37fdff27b1027b354e8f764ba3648312b73109dfa0839f16b04998d400aa133be6b57020d

==========
```

Authorizing:

Now that we have a token, let's have a look at how a service can authorize
a request based on a token.

To do so, the service provides an authorizer, built with:

- `facts` about the request (current time, resource being accessed, type of the operation)
- `facts` or `rules` about access control (ACLs, access matrix)
- `checks` to apply some restrictions (every check has to pass for the authorization to succeed)
- `policies` which are tried in order, the first one to match decides if the authorization passes or fails

In our case, we'll assume the token is used for a `write` operation on the `resource1` resource.

**authorizer.datalog**

```
// request-specific data
operation("write");
resource("resource1");
time(2021-12-21T20:00:00Z);
// server-side ACLs
right("1234", "resource1", "read");
right("1234", "resource1", "write");
right("1234", "resource2", "read");
is_allowed($user, $res, $op) <-
user($user),
resource($res),
operation($op),
right($user, $res, $op);
// the request can go through if the current user
// is allowed to perform the current operation
// on the current resource
allow if is_allowed($user, $resource, $op);
```

There's a bit more happening here: the first three facts give info about
the request. Then we have ACLs (they can be declared statically for a small,
static user base, or fetched from DB based on the token user).

`is_allowed` is more interesting: it's a `rule`. If, given a user,
a resource and an operation, there's a `right`  fact that puts them
all together, then we know the request can go through.

With all that done, we can go ahead and check:

```
❯ bisque inspect - --verify-with-file authorizer.datalog --public-key 41e77e842e5c952a29233992dc8ebbedd2d83291a89bb0eec34457e723a69526
Please input a base64-encoded bisque, followed by <enter> and ^D
En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBw-OHV3egI0IVjiC1vdB7WZ__t0FCvB2s-81PexdwuqxpAolMr9XDP7T44qgdXxtumc2P3O93pCHaGSuBUs3_f8nsQJ7NU6PdkujZIMStzEJ36CDnxawSZjUAKoTO-a1cCDSIiCiBPsG53WHcpxeydjSpFYNYnvPAeM1tVBvOEG9SQgMrzbw==
Authority block:
== Datalog ==
user("1234");

== Revocation id ==
a2532bf570cfed3e38aa0757c6dba67363f73bdde90876864ae054b37fdff27b1027b354e8f764ba3648312b73109dfa0839f16b04998d400aa133be6b57020d

==========
```

Attenuating a token:

One of strengths is the ability to attenuate tokens, restricting their use.
Attenuating a token is done by appending a block containing a check. Let's
attenuate our first token by adding a TTL (Time To Live) check:
this way the new token will only be usable for a given period of time.
In the authorizer above, we provided a time fact, that was not used in
a policy or a check. We can add a block that will make sure the token
is not used after a certain date.

**block1.datalog**

```
check if time($time), $time <= 2021-12-20T00:00:00Z;
```

The check requires two things to suceed: first, the current time must be
declared through the `time()` fact, and the current time must be smaller
than `2021-12-20T00:00:00Z`.

We can create a new token by appending this block to our existing token:

```
❯ bisque attenuate - --block-file 'block1.bisque-datalog'
Please input a base64-encoded bisque, followed by <enter> and ^D
En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBw-OHV3egI0IVjiC1vdB7WZ__t0FCvB2s-81PexdwuqxpAolMr9XDP7T44qgdXxtumc2P3O93pCHaGSuBUs3_f8nsQJ7NU6PdkujZIMStzEJ36CDnxawSZjUAKoTO-a1cCDSIiCiBPsG53WHcpxeydjSpFYNYnvPAeM1tVBvOEG9SQgMrzbw==
En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBw-OHV3egI0IVjiC1vdB7WZ__t0FCvB2s-81PexdwuqxpAolMr9XDP7T44qgdXxtumc2P3O93pCHaGSuBUs3_f8nsQJ7NU6PdkujZIMStzEJ36CDnxawSZjUAKoTO-a1cCDRqUAQoqGAMyJgokCgIIGxIGCAUSAggFGhYKBAoCCAUKCAoGIICP_40GCgQaAggCEiQIABIgkzpUMZubXcd8K7mWNchjb0D2QXeYoWtlZw2KMryKubUaQOFlx4iPKUqKeJrEH4MKO7tjM3H9z1rYbOj-gKGTtYJ4bac0kIoWl9v_7q7qN7fQJJgj0IU4jx4_QhxIk9SeigMiIgogqvHkuXrYkoMRvKgT9zNV4BEKC5W2K8L7NcGiX44ASwE=
```

```
❯ bisque inspect - --verify-with-file authorizer.datalog --public-key 41e77e842e5c952a29233992dc8ebbedd2d83291a89bb0eec34457e723a69526
Please input a base64-encoded bisque, followed by <enter> and ^D
En0KEwoEMTIzNBgDIgkKBwgKEgMYgAgSJAgAEiBw-OHV3egI0IVjiC1vdB7WZ__t0FCvB2s-81PexdwuqxpAolMr9XDP7T44qgdXxtumc2P3O93pCHaGSuBUs3_f8nsQJ7NU6PdkujZIMStzEJ36CDnxawSZjUAKoTO-a1cCDRqUAQoqGAMyJgokCgIIGxIGCAUSAggFGhYKBAoCCAUKCAoGIICP_40GCgQaAggCEiQIABIgkzpUMZubXcd8K7mWNchjb0D2QXeYoWtlZw2KMryKubUaQOFlx4iPKUqKeJrEH4MKO7tjM3H9z1rYbOj-gKGTtYJ4bac0kIoWl9v_7q7qN7fQJJgj0IU4jx4_QhxIk9SeigMiIgogqvHkuXrYkoMRvKgT9zNV4BEKC5W2K8L7NcGiX44ASwE=
Authority block:
== Datalog ==
user("1234");

== Revocation id ==
a2532bf570cfed3e38aa0757c6dba67363f73bdde90876864ae054b37fdff27b1027b354e8f764ba3648312b73109dfa0839f16b04998d400aa133be6b57020d

==========

Block n°1:
== Datalog ==
check if time($time), $time <= 2021-12-20T00:00:00Z;

== Revocation id ==
e165c7888f294a8a789ac41f830a3bbb633371fdcf5ad86ce8fe80a193b582786da734908a1697dbffeeaeea37b7d0249823d085388f1e3f421c4893d49e8a03

==========
```

Here it failed because the date provided in the authorizer (`time(2021-12-21T20:00:00Z)`)
is greater than the expiration date specified in the check (`check if time($time)`, 
`$time <= 2021-12-20T00:00:00+00:00`).

Datalog authorization policies:

The loads facts, data that can comes from the token (user id), from the request
(file name, read or write access, current date) or the application's internal
databases (users, roles, rights).

Then it uses those facts to decide whether the request is allowed to go trough.
It does so through two mechanisms:

- a check list: each check validates the presence of one or more facts.
  Every check must succeed for the request to be allowed. Example:
  `check if time($time), $time < 2022-01-01T00:00:00Z`, for an expiration date.
- allow/deny policies: a list of policies that are tried in sequence until one
  of them matches. If it is an allow policy, the request is accepted, while if
  it is a deny policy the request is denied. If no policy matches, the request
  is also denied. Example:
  `allow if resource($res), operation($op), right($res, $op)`.

Allow/deny policies can only be defined in the application, while checks can
come from the application or the token: tokens can only add restrictions
(through checks), while only the application can approve a token (by defining
an allow policy).

Tokens can be attenuated by appending a block containing checks.

What algorithm should I use for sign jwt
------------------------------------------

[jwt.io](https://jwt.io/) referred that there are many algorithms, which are:

```
HS256 HS384 HS512

RS256 RS384 RS512

ES256 ES384 ES512

PS256 PS384 PS512
```

What are the differences between these algorithms? And what is the most secure
one? And if I am going to store the jwt in cookies what algorithm should I use?

For anyone else finding this question, I suggest...
[Understanding RSA signing for JWT](https://stackoverflow.com/questions/38588319/understanding-rsa-signing-for-jwt)

Specifications - JWA/JWE/JWK/JWS/JWT
--------------------------------------

1. JWA - JSON Web Algorithms
2. JWE - JSON Web Encryption
3. JWK - JSON Web Key
4. JWS - JSON Web Signature
5. JWT - JSON Web Token

The JWT specification supports several algorithms for cryptographic signing.
This library currently supports:

- `ES256K` - ECDSA signature algorithm with secp256k1 curve using SHA-256 hash algorithm ECDSA using secp256k1 curve and SHA-256
- `ES256`  - ECDSA signature algorithm using SHA-256 hash algorithm                      ECDSA P curve and SHA
- `ES384`  - ECDSA signature algorithm using SHA-384 hash algorithm                      ECDSA P curve and SHA
- `ES512`  - ECDSA signature algorithm using SHA-512 hash algorithm                      ECDSA P curve and SHA
- `EdDSA`  - Ed25519 signature using SHA-512 and Ed448 signature using SHA-3             EdDSA RFC 8037
             Ed25519 and Ed448 provide 128-bit and 224-bit security respectively
- `HS256`  - HMAC using SHA-256 hash algorithm                                           HMAC SHA
- `HS384`  - HMAC using SHA-384 hash algorithm                                           HMAC SHA
- `HS512`  - HMAC using SHA-512 hash algorithm                                           HMAC SHA
- `PS256`  - RSASSA-PSS signature using SHA-256 and MGF1 padding with SHA-256            RSASSA-PSS SHA
- `PS384`  - RSASSA-PSS signature using SHA-384 and MGF1 padding with SHA-384            RSASSA-PSS SHA
- `PS512`  - RSASSA-PSS signature using SHA-512 and MGF1 padding with SHA-512            RSASSA-PSS SHA
- `RS256`  - RSASSA-PKCS1-v1_5 signature algorithm using SHA-256 hash algorithm          RSASSA-PKCS-v1_5 SHA
- `RS384`  - RSASSA-PKCS1-v1_5 signature algorithm using SHA-384 hash algorithm          RSASSA-PKCS-v1_5 SHA
- `RS512`  - RSASSA-PKCS1-v1_5 signature algorithm using SHA-512 hash algorithm          RSASSA-PKCS-v1_5 SHA


`alg` (Algorithm) Header Parameters Values for JWS

```
λ import Jose.Jwa (JwsAlg(ES256,ES384,ES512,EdDSA,HS256,HS384,HS512,RS256,RS384,RS512))
λ generateSymmetricKey 256 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.ES256))
λ generateSymmetricKey 384 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.ES384))
λ generateSymmetricKey 512 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.ES512))
λ generateSymmetricKey 256 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.EdDSA))
λ generateSymmetricKey 384 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.EdDSA))
λ generateSymmetricKey 512 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.EdDSA))
λ generateSymmetricKey 256 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.HS256))
λ generateSymmetricKey 384 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.HS384))
λ generateSymmetricKey 512 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.HS512))
λ generateSymmetricKey 256 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.RS256))
λ generateSymmetricKey 384 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.RS384))
λ generateSymmetricKey 512 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.RS512))

λ generateRsaKeyPair   256 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.ES256))
λ generateRsaKeyPair   384 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.ES384))
λ generateRsaKeyPair   512 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.ES512))
λ generateRsaKeyPair   256 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.EdDSA))
λ generateRsaKeyPair   384 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.EdDSA))
λ generateRsaKeyPair   512 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.EdDSA))
λ generateRsaKeyPair   256 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.HS256))
λ generateRsaKeyPair   384 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.HS384))
λ generateRsaKeyPair   512 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.HS512))
λ generateRsaKeyPair   256 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.RS256))
λ generateRsaKeyPair   384 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.RS384))
λ generateRsaKeyPair   512 (KeyId "helloWorld") Sig (Just (Signed Jose.Jwa.RS512))
```

```
λ import Crypto.PubKey.ECC.Generate
λ import Crypto.PubKey.ECC.Types

λ :i CurveName

λ curve = getCurveByName SEC_p256k1
λ generate curve

λ curve = getCurveByName SEC_p384r1
λ generate curve

λ curve = getCurveByName SEC_p521r1
λ generate curve
```

```
λ import Crypto.ECC
λ import Crypto.PubKey.ECC.Generate
λ import Crypto.PubKey.ECDSA as ECDSA
λ import Data.Proxy

λ generate (Proxy :: Proxy Curve_P256R1)
```

```
λ import Crypto.PubKey.ECC.Generate
λ import Crypto.PubKey.ECC.Types

λ :i CurveName

λ curve = getCurveByName SEC_p256k1
λ generate curve

λ curve = getCurveByName SEC_p384r1
λ generate curve

λ curve = getCurveByName SEC_p521r1
λ generate curve
```

-- Jose.Jwa
-- JwsAlg - subset of the signature algorithms from the JWA Spec.
-- ES256
-- ES384
-- ES512
-- EdDSA
-- HS256
-- HS384
-- HS512
-- RS256
-- RS384
-- RS512
-- None
-- JweAlg - A subset of the key management algorithms from the JWA Spec.
-- A128KW
-- A192KW
-- A256KW
-- RSA1_5
-- RSA_OAEP
-- RSA_OAEP_256
-- Enc - Content encryption algorithms from the JWA Spec.
-- A128CBC_HS256
-- A128GCM
-- A192CBC_HS384
-- A192GCM
-- A256CBC_HS512
-- A256GCM

-- [RSA1_5, RSA_OAEP, RSA_OAEP_256, A128KW, A192KW, A256KW] To encrypt content-encryption
-- key and can be either an RSA or AES-keywrap algorithm. You need to generate a suitable
-- key to use with this, or load one from storage. With RSA anyone can send you  a JWE if
-- they have a copy of your public key.
-- [A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM, A256GCM] AES algorithm
-- used to encrypt the content of your token, for which a single-use key is generated
-- internally.  AES is much faster and creates shorter tokens,  but both the encoder  and
-- decoder of the token need to have a copy of the key, which they must keep secret.

-- import Jose.Jwe
-- import Jose.Jwa
-- import Jose.Jwk (generateRsaKeyPair, generateSymmetricKey, KeyUse(Enc), KeyId)
-- (kPub, kPr) <- generateRsaKeyPair 256 (KeyId "helloWorld") Enc Nothing
-- (kPub, kPr) <- generateRsaKeyPair 384 (KeyId "helloWorld") Enc Nothing
-- (kPub, kPr) <- generateRsaKeyPair 512 (KeyId "helloWorld") Enc Nothing
-- Right (Jwt jwt) <- jwkEncode RSA_OAEP A128GCM kPub (Claims "secret claims")
-- Right (Jwe (hdr, claims)) <- jwkDecode kPr jwt
-- claims
-- "secret claims"
--
-- aesKey <- generateSymmetricKey 16 (KeyId "helloWorld") Enc Nothing
-- Right (Jwt jwt) <- jwkEncode A128KW A128GCM aesKey (Claims "secret claims")
-- Right (Jwe (hdr, claims)) <- jwkDecode aesKey jwt
-- claims
-- "secret claims"

-- {"typ": "JWT", "kid": "123", "alg": "RS256"}
-- For example, a JWK containing an EdDSA public key would look like the following:
-- {"kty": "OKP", "alg": "EdDSA", "crv": "Ed25519", "x": "60mR98SQlHUSeLeIu7TeJBTLRG10qlcDLU4AJjQdqMQ"}

-- jwkEncode
-- ecDecode
-- ed25519Encode
-- ed25519Decode
-- ed448Encode
-- ed448Decode
-- hmacEncode
-- hmacDecode
-- rsaEncode
-- rsaDecode

-- I'm using some of the functions in Crypto.PubKey.RSA, and wish to read
-- and write PEM files compatible with openssl.
-- I need functionality equivalent to these functions from OpenSSL.PEM:
-- writePKCS8PrivateKey
-- readPrivateKey
-- writePublicKey
-- readPublicKey
--
-- Are there functions in some library compatible with Crypto.PubKey.RSA to do this?
-- https://github.com/haskell-crypto/cryptonite/issues/69
-- https://hackage.haskell.org/package/cryptostore
-- https://github.com/ocheron/cryptostore
-- https://hackage.haskell.org/package/Z-Botan
-- https://github.com/ZHaskell/z-botan
-- https://hackage.haskell.org/package/jose-0.11
-- https://github.com/frasertweedale/hs-jose
-- https://hackage.haskell.org/package/crypton-1.0.1
-- https://hackage.haskell.org/package/crypton-1.0.1/docs/Crypto-Hash.html
-- https://hackage.haskell.org/package/jose-jwt
-- https://datatracker.ietf.org/doc/html/rfc7518#section-3

--
-- encode jwks  (JwsEncoding RS256) (Claims . toStrict . Aeson.encode $ claim)
--
--{-# LANGUAGE OverloadedStrings #-}
--
-- import Web.Scotty
-- import Data.Text.Lazy (Text, pack)
-- import Web.JWT (encodeSigned, secret, decodeAndVerrifySignature, defaultJWTClaimsSet)
-- import Data.Aeson (object, (.=))
--
-- Define a secret key
-- jwtSecret = secret "supersecretkey"
--
-- Generate JWT Token
-- generteToken :: Text -> Text
-- generteToken username = encodeSigned jwtSecret mempty (defaultJWTClaimsSet username)
--
-- Verify JWT
-- verifyToken :: Text -> Bool
-- verifyToken token = case decodeAndVerifySignature jwtSecret token of
--   Just -> True
--   Nothing -> False

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

### Errors

```
import Data.ByteString       as BS
import Data.ByteString.Char8 as CH

λ :reload
λ :load test/Spec/Auth/Kailua/SampleReader.hs

λ filename = "test031_limit_expired_token.bc" :: String
λ proba <- readSamplesFile
λ SampleFile {root_private_key = sk, root_public_key = pk, testcases = ttt} = proba
λ token <- buildToken sk "123"
λ BS.writeFile ("test/samples/current/" <> filename) (serialize token)

λ xxx <- BS.readFile ("test/samples/current/" <> filename)
λ parsingOptions = ParserConfig {encoding = RawBytes, isRevoked = const $ pure False, getPublicKey = pure pk}
λ parseWith parsingOptions xxx
```

### 10 Oct 2024 by Oleg G.Kapranov
