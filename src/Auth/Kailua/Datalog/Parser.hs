{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE RecordWildCards       #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TemplateHaskellQuotes #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeApplications      #-}
{-|
  Module      : Auth.Kailua.Datalog.Parser
  Copyright   : updated © Oleg G.Kapranov, 2025
  License     : MIT
  Maintainer  : lugatex@yahoo.com
  The Datalog Parser
-}
module Auth.Kailua.Datalog.Parser ( authorizer
                                  , authorizerParser
                                  , block
                                  , blockParser
                                  , check
                                  , checkParser
                                  , expressionParser
                                  , fact
                                  , parseAuthorizer
                                  , parseBlock
                                  , parseWithParams
                                  , policyParser
                                  , predicate
                                  , predicateParser
                                  , query
                                  , rule
                                  , ruleParser
                                  , termParser
                                  ) where

import Auth.Kailua.Crypto                       ( PublicKey
                                                , readEd25519PublicKey
                                                )
import Auth.Kailua.Datalog.AST                  ( Authorizer
                                                , Authorizer' (..)
                                                , AuthorizerElement' (..)
                                                , Binary (..)
                                                , Block
                                                , Block' (..)
                                                , BlockElement' (..)
                                                , Check
                                                , Check' (..)
                                                , CheckKind (..)
                                                , DatalogContext (..)
                                                , EvaluationContext (..)
                                                , Expression' (..)
                                                , Fact
                                                , IsWithinSet (..)
                                                , PkOrSlice (..)
                                                , Policy'
                                                , PolicyType (..)
                                                , Predicate
                                                , Predicate' (..)
                                                , PredicateOrFact (..)
                                                , Query
                                                , QueryItem' (..)
                                                , Rule
                                                , Rule' (..)
                                                , RuleScope' (..)
                                                , SetType
                                                , Slice (..)
                                                , Term' (..)
                                                , Unary (..)
                                                , Value
                                                , VariableType
                                                , elementToAuthorizer
                                                , elementToBlock
                                                , makeQueryItem
                                                , makeRule
                                                , substituteAuthorizer
                                                , substituteBlock
                                                )
import Auth.Kailua.Datalog.Types                ( Parser
                                                , SemanticError (..)
                                                , Span
                                                )
import Auth.Kailua.Utils                        (decodeHex)
import Control.Monad                            (join)
import qualified Control.Monad.Combinators.Expr as Expr
import Data.Bifunctor
import Data.ByteString                          (ByteString)
import qualified Data.ByteString.Char8          as C8
import Data.Char
import Data.Either                              (partitionEithers)
import Data.Function                            ((&))
import Data.Int                                 (Int64)
import Data.List.NonEmpty                       (NonEmpty)
import Data.Map.Strict                          (Map)
import Data.Maybe                               (isJust)
import Data.Set                                 (Set)
import qualified Data.Set                       as Set
import Data.Text                                (Text)
import qualified Data.Text                      as T
import Data.Time                                ( UTCTime
                                                , defaultTimeLocale
                                                , parseTimeM
                                                )
import Instances.TH.Lift                        ()
import Language.Haskell.TH
import Language.Haskell.TH.Quote                (QuasiQuoter (..))
import Text.Megaparsec
import Validation                               ( Validation (..)
                                                , validationToEither
                                                )
import qualified Text.Megaparsec.Char           as C
import qualified Text.Megaparsec.Char.Lexer     as L

l :: Parser a -> Parser a
l = L.lexeme $ L.space C.space1 (L.skipLineComment "//") empty

run :: Parser a -> Text -> Either String a
run p = first errorBundlePretty . runParser (l (pure ()) *> l p <* eof) ""

getSpan :: Parser a -> Parser (Span, a)
getSpan p = do
  begin <- getOffset
  a <- p
  end <- getOffset
  pure ((begin, end), a)

registerError :: (Span -> SemanticError) -> Span -> Parser a
registerError mkError sp = do
  let err = FancyError (fst sp) (Set.singleton (ErrorCustom $ mkError sp))
  registerParseError err
  pure $ error "delayed parsing error"

forbid :: (Span -> SemanticError) -> Parser a -> Parser b
forbid mkError p = do
  (sp, _) <- getSpan p
  registerError mkError sp

variableParser :: Parser Text
variableParser =
  C.char '$' *> takeWhile1P (Just "_, :, or any alphanumeric char") (\c -> c == '_' || c == ':' || isAlphaNum c)

haskellVariableParser :: Parser Text
haskellVariableParser = l $ do
  _ <- chunk "{"
  leadingUS <- optional $ C.char '_'
  x <- if isJust leadingUS then C.letterChar else C.lowerChar
  xs <- takeWhileP (Just "_, ', or any alphanumeric char") (\c -> c == '_' || c == '\'' || isAlphaNum c)
  _ <- C.char '}'
  pure . maybe id T.cons leadingUS $ T.cons x xs

hexParser :: Parser ByteString
hexParser = do
  (sp, hexStr) <- getSpan $ C8.pack <$> some C.hexDigitChar
  case decodeHex hexStr of
    Left e   -> registerError (InvalidBs e) sp
    Right bs -> pure bs

rfc3339DateParser :: Parser UTCTime
rfc3339DateParser = do
  let parseDate = parseTimeM False defaultTimeLocale "%FT%T%Q%EZ"
  input <- sequenceA [
      try (sequenceA [
        C.digitChar,
        C.digitChar,
        C.digitChar,
        C.digitChar,
        C.char '-',
        C.digitChar,
        C.digitChar,
        C.char '-',
        C.digitChar,
        C.digitChar,
        C.char 'T'
      ]),
      pure <$> C.digitChar,
      pure <$> C.digitChar,
      pure <$> C.char ':',
      pure <$> C.digitChar,
      pure <$> C.digitChar,
      pure <$> C.char ':',
      pure <$> C.digitChar,
      pure <$> C.digitChar,
      foldMap join <$> optional (sequenceA [
        pure <$> C.char '.',
        some C.digitChar
      ]),
      choice [
        pure <$> C.char 'Z',
        sequenceA [
           choice [C.char '+', C.char '-'],
           C.digitChar,
           C.digitChar,
           C.char ':',
           C.digitChar,
           C.digitChar
        ]
      ]
    ]
  parseDate $ join input

intParser :: Parser Int64
intParser = do
  integer :: Integer <- L.signed C.space L.decimal <?> "(signed) integer"
  if integer < fromIntegral (minBound @Int64)
     || integer > fromIntegral (maxBound @Int64)
  then fail "integer literals must fit in the int64 range"
  else pure $ fromIntegral integer

termParser :: Parser (VariableType inSet pof) -> Parser (SetType inSet 'WithSlices) -> Parser (Term' inSet pof 'WithSlices)
termParser parseVar parseSet = l $ choice
  [ Antiquote . Slice <$> haskellVariableParser <?> "parameter (eg. {paramName})"
  , Variable <$> parseVar <?> "datalog variable (eg. $variable)"
  , TermSet <$> parseSet <?> "set (eg. [1,2,3])"
  , LBytes <$> (chunk "hex:" *> hexParser) <?> "hex-encoded bytestring (eg. hex:00ff99)"
  , LDate <$> rfc3339DateParser <?> "RFC3339-formatted timestamp (eg. 2022-11-29T00:00:00Z)"
  , LInteger <$> intParser <?> "(signed) integer"
  , LString . T.pack <$> (C.char '"' *> manyTill L.charLiteral (C.char '"')) <?> "string literal"
  , LBool <$> choice [ True <$ chunk "true"
                     , False <$ chunk "false"
                     ]
          <?> "boolean value (eg. true or false)"
  ]

setParser :: Parser (Set (Term' 'WithinSet 'InFact 'WithSlices))
setParser = do
  _ <- l $ C.char '['
  ts <- sepBy (termParser (forbid VarInSet variableParser) (forbid NestedSet setParser)) (l $ C.char ',')
  _ <- l $ C.char ']'
  pure $ Set.fromList ts

factTermParser :: Parser (Term' 'NotWithinSet 'InFact 'WithSlices)
factTermParser = termParser (forbid VarInFact variableParser)
                            setParser

predicateTermParser :: Parser (Term' 'NotWithinSet 'InPredicate 'WithSlices)
predicateTermParser = termParser variableParser
                                 setParser

publicKeyParser :: Parser PublicKey
publicKeyParser = do
  (sp, hexStr) <- getSpan $ C8.pack <$> (chunk "ed25519/" *> some C.hexDigitChar)
  case decodeHex hexStr of
    Left e -> registerError (InvalidPublicKey e) sp
    Right bs -> case readEd25519PublicKey bs of
      Nothing -> registerError (InvalidPublicKey "Invalid ed25519 public key") sp
      Just pk -> pure pk

predicateParser' :: Parser (Term' 'NotWithinSet pof 'WithSlices)
                 -> Parser (Predicate' pof 'WithSlices)
predicateParser' parseTerm = l $ do
  name <- try . (<?> "predicate name") $ do
    x      <- C.letterChar
    xs     <- takeWhileP (Just "_, :, or any alphanumeric char") (\c -> c == '_' || c == ':' || isAlphaNum c)
    _      <- l $ C.char '('
    pure $ T.cons x xs
  terms  <- sepBy1 parseTerm (l $ C.char ',')
  _      <- l $ C.char ')'
  pure Predicate {
    name,
    terms
  }

factParser :: Parser (Predicate' 'InFact 'WithSlices)
factParser = predicateParser' factTermParser

predicateParser :: Parser (Predicate' 'InPredicate 'WithSlices)
predicateParser = predicateParser' predicateTermParser

table :: [[Expr.Operator Parser (Expression' 'WithSlices)]]
table =
  let infixL name op = Expr.InfixL (EBinary op <$ l (chunk name) <?> "infix operator")
      infixN name op = Expr.InfixN (EBinary op <$ l (chunk name) <?> "infix operator")
      prefix name op = Expr.Prefix (EUnary op <$  l (chunk name) <?> "prefix operator")
   in [ [ prefix "!" Negate]
      , [ infixL  "*" Mul
        , infixL  "/" Div
        ]
      , [ infixL  "+" Add
        , infixL  "-" Sub
        ]
      , [ infixL  "& " BitwiseAnd ]
      , [ infixL  "| " BitwiseOr  ]
      , [ infixL  "^" BitwiseXor ]
      , [ infixN  "<=" LessOrEqual
        , infixN  ">=" GreaterOrEqual
        , infixN  "<"  LessThan
        , infixN  ">"  GreaterThan
        , infixN  "==" Equal
        , infixN  "!=" NotEqual
        ]
      , [ infixL "&&" And ]
      , [ infixL "||" Or ]
      ]

binaryMethodParser :: Parser (Expression' 'WithSlices -> Expression' 'WithSlices)
binaryMethodParser = do
  _ <- C.char '.'
  method <- choice
    [ Contains     <$ chunk "contains"
    , Intersection <$ chunk "intersection"
    , Union        <$ chunk "union"
    , Prefix       <$ chunk "starts_with"
    , Suffix       <$ chunk "ends_with"
    , Regex        <$ chunk "matches"
    ]
  _ <- l $ C.char '('
  e2 <- l expressionParser
  _ <- l $ C.char ')'
  pure $ \e1 -> EBinary method e1 e2

unaryMethodParser :: Parser (Expression' 'WithSlices -> Expression' 'WithSlices)
unaryMethodParser = do
  _ <- C.char '.'
  method <- Length <$ chunk "length"
  _ <- l $ chunk "()"
  pure $ EUnary method

methodsParser :: Parser (Expression' 'WithSlices)
methodsParser = do
  e1 <- exprTerm
  methods <- some (try binaryMethodParser <|> unaryMethodParser)
  pure $ foldl (&) e1 methods

unaryParens :: Parser (Expression' 'WithSlices)
unaryParens = do
  _ <- l $ C.char '('
  e <- l expressionParser
  _ <- l $ C.char ')'
  pure $ EUnary Parens e

exprTerm :: Parser (Expression' 'WithSlices)
exprTerm = choice
  [ unaryParens <?> "parens"
  , EValue <$> predicateTermParser
  ]

expressionParser :: Parser (Expression' 'WithSlices)
expressionParser =
  let base = choice [ try methodsParser
                    , exprTerm
                    ]
   in Expr.makeExprParser base table

scopeParser :: Bool -> Parser (Set.Set (RuleScope' 'Repr 'WithSlices))
scopeParser inAuthorizer = (<?> "scope annotation") $ do
  _ <- l $ chunk "trusting "
  let elemParser = do
        (sp, s) <- getSpan $ choice [ OnlyAuthority <$  chunk "authority"
                                    , Previous      <$  chunk "previous"
                                    , BlockId       <$>
                                       choice [ PkSlice <$> haskellVariableParser <?> "parameter (eg. {paramName})"
                                              , Pk <$> publicKeyParser <?> "public key (eg. ed25519/00ff99)"
                                              ]
                                    ]
        if inAuthorizer && s == Previous
        then registerError PreviousInAuthorizer sp
        else pure s
  Set.fromList <$> sepBy1 (l elemParser)
                          (l $ C.char ',')

ruleBodyParser :: Bool -> Parser ([Predicate' 'InPredicate 'WithSlices], [Expression' 'WithSlices], Set.Set (RuleScope' 'Repr 'WithSlices))
ruleBodyParser inAuthorizer = do
  let predicateOrExprParser =
            Left  <$> (predicateParser <?> "predicate")
        <|> Right <$> (expressionParser <?> "expression")
  elems <- l $ sepBy1 (l predicateOrExprParser)
                      (l $ C.char ',')
  scope <- option Set.empty $ scopeParser inAuthorizer
  let (predicates, expressions) = partitionEithers elems
  pure (predicates, expressions, scope)

ruleParser :: Bool -> Parser (Rule' 'Repr 'WithSlices)
ruleParser inAuthorizer = do
  begin <- getOffset
  rhead <- try $ l predicateParser <* l (chunk "<-")
  (body, expressions, scope) <- ruleBodyParser inAuthorizer
  end <- getOffset
  case makeRule rhead body expressions scope of
    Failure vs -> registerError (UnboundVariables vs) (begin, end)
    Success r  -> pure r

queryItemParser :: Bool -> Parser (QueryItem' 'Repr 'WithSlices)
queryItemParser inAuthorizer = do
  (sp, (predicates, expressions, scope)) <- getSpan $ ruleBodyParser inAuthorizer
  case makeQueryItem predicates expressions scope of
    Failure e  -> registerError (UnboundVariables e) sp
    Success qi -> pure qi

queryParser :: Bool -> Parser [QueryItem' 'Repr 'WithSlices]
queryParser inAuthorizer =
   sepBy1 (queryItemParser inAuthorizer) (l $ C.string' "or" <* C.space)
     <?> "datalog query"

checkParser :: Bool -> Parser (Check' 'Repr 'WithSlices)
checkParser inAuthorizer = do
  cKind <- l $ choice [ One <$ chunk "check if"
                      , All <$ chunk "check all"
                      ]
  cQueries <- queryParser inAuthorizer
  pure Check{..}

policyParser :: Parser (Policy' 'Repr 'WithSlices)
policyParser = do
  policy <- l $ choice [ Allow <$ chunk "allow if"
                       , Deny  <$ chunk "deny if"
                       ]
  (policy, ) <$> queryParser True

blockElementParser :: Bool -> Parser (BlockElement' 'Repr 'WithSlices)
blockElementParser inAuthorizer = choice
  [ BlockCheck   <$> checkParser inAuthorizer <* C.char ';' <?> "check"
  , BlockRule    <$> ruleParser  inAuthorizer <* C.char ';' <?> "rule"
  , BlockFact    <$> factParser <* C.char ';' <?> "fact"
  ]

authorizerElementParser :: Parser (AuthorizerElement' 'Repr 'WithSlices)
authorizerElementParser = choice
  [ AuthorizerPolicy  <$> policyParser <* C.char ';' <?> "policy"
  , BlockElement    <$> blockElementParser True
  ]

blockParser :: Parser (Block' 'Repr 'WithSlices)
blockParser = do
  bScope <- option Set.empty $ l (scopeParser False <* C.char ';' <?> "scope annotation")
  elems <- many $ l $ blockElementParser False
  pure $ (foldMap elementToBlock elems) { bScope = bScope }

authorizerParser :: Parser (Authorizer' 'Repr 'WithSlices)
authorizerParser = do
  bScope <- option Set.empty $ l (scopeParser True <* C.char ';' <?> "scope annotation")
  elems <- many $ l authorizerElementParser
  let addScope a = a { vBlock = (vBlock a) { bScope = bScope } }
  pure $ addScope $ foldMap elementToAuthorizer elems

parseWithParams :: Parser (a 'WithSlices)
                -> (Map Text Value -> Map Text PublicKey -> a 'WithSlices -> Validation (NonEmpty Text) (a 'Representation))
                -> Text
                -> Map Text Value -> Map Text PublicKey
                -> Either (NonEmpty Text) (a 'Representation)
parseWithParams parser substitute input termMapping keyMapping = do
  withSlices <- first (pure . T.pack) $ run parser input
  validationToEither $ substitute termMapping keyMapping withSlices

parseBlock :: Text -> Map Text Value -> Map Text PublicKey -> Either (NonEmpty Text) Block
parseBlock = parseWithParams blockParser substituteBlock

parseAuthorizer :: Text -> Map Text Value -> Map Text PublicKey -> Either (NonEmpty Text) Authorizer
parseAuthorizer = parseWithParams authorizerParser substituteAuthorizer

compileParser :: Parser a -> (a -> Q Exp) -> String -> Q Exp
compileParser p build =
  either fail build . run p . T.pack

rule :: QuasiQuoter
rule = QuasiQuoter
  { quoteExp = compileParser (ruleParser False) $ \result -> [| result :: Rule |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

predicate :: QuasiQuoter
predicate = QuasiQuoter
  { quoteExp = compileParser predicateParser $ \result -> [| result :: Predicate |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

fact :: QuasiQuoter
fact = QuasiQuoter
  { quoteExp = compileParser factParser $ \result -> [| result :: Fact |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

check :: QuasiQuoter
check = QuasiQuoter
  { quoteExp = compileParser (checkParser False) $ \result -> [| result :: Check |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

block :: QuasiQuoter
block = QuasiQuoter
  { quoteExp = compileParser blockParser $ \result -> [| result :: Block |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

authorizer :: QuasiQuoter
authorizer = QuasiQuoter
  { quoteExp = compileParser authorizerParser $ \result -> [| result :: Authorizer |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

query :: QuasiQuoter
query = QuasiQuoter
  { quoteExp = compileParser (queryParser False) $ \result -> [| result :: Query |]
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }
