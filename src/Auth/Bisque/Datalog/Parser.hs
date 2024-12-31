{-# LANGUAGE AllowAmbiguousTypes   #-}
{-# LANGUAGE ConstraintKinds       #-}
{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE DeriveLift            #-}
{-# LANGUAGE DerivingStrategies    #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE LambdaCase            #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns        #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TemplateHaskell       #-}
{-# LANGUAGE TupleSections         #-}
{-# LANGUAGE TypeApplications      #-}
{-# LANGUAGE TypeFamilies          #-}
{-|
  Module     : Auth.Bisque.Datalog.Parser
  Copyright  : updated © Oleg G.Kapranov, 2024
  License    : MIT
  Maintainer : lugatex@yahoo.com
  The Datalog engine, tasked with deriving new facts from existing facts
  and rules, as well as matching available facts against checks and policies
-}
module Auth.Bisque.Datalog.Parser ( HasParsers
                                  , HasTermParsers
                                  , authorizer
                                  , authorizerParser
                                  , block
                                  , blockParser
                                  , check
                                  , checkParser
                                  , expressionParser
                                  , fact
                                  , policyParser
                                  , predicate
                                  , predicateParser
                                  , query
                                  , rule
                                  , ruleParser
                                  , termParser
                                  ) where

import Auth.Bisque.Datalog.AST
import Auth.Bisque.Utils                        (decodeHex)
import Control.Applicative                      (optional, (<|>))
import qualified Control.Monad.Combinators.Expr as Expr
import qualified Data.Foldable                  as F
import Data.Attoparsec.Text
import qualified Data.Attoparsec.Text           as A
import Data.ByteString                          (ByteString)
import Data.Char                                (isAlphaNum, isLetter, isSpace)
import Data.Either                              (partitionEithers)
import Data.Functor                             (void, ($>))
import Data.Text                                (Text, pack, unpack)
import qualified Data.Text                      as T
import Data.Text.Encoding                       (encodeUtf8)
import Data.Time                                (UTCTime, defaultTimeLocale, parseTimeM)
import Data.Void                                (Void)
import Data.Set                                 as Set
import Instances.TH.Lift                        ()
import Language.Haskell.TH.Quote
import Language.Haskell.TH.Syntax               (Lift, Q, Exp)

commaList0 :: Parser a -> Parser [a]
commaList0 p = sepBy p (skipSpace *> char ',')

termParser :: forall inSet pof ctx . ( HasTermParsers inSet pof ctx) => Parser (Term' inSet pof ctx)
termParser = skipSpace *> choice
  [ Antiquote <$> ifPresent "slice" (Slice <$> (string "${" *> many1 letter <* char '}'))
  , Variable <$> ifPresent "var" variableNameParser
  , TermSet <$> parseSet @inSet @ctx
  , LBytes <$> hexBsParser
  , LDate <$> rfc3339DateParser
  , LInteger <$> signed decimal
  , LString <$> litStringParser
  , LBool <$> choice [ string "true"  $> True, string "false" $> False ]
  ]

type HasTermParsers inSet pof ctx =
  ( ConditionalParse (SliceType 'QuasiQuote)                   (SliceType ctx)
  , ConditionalParse (VariableType 'NotWithinSet 'InPredicate) (VariableType inSet pof)
  , SetParser inSet ctx
  )

type HasParsers pof ctx = HasTermParsers 'NotWithinSet pof ctx

variableNameParser :: Parser Text
variableNameParser = char '$' *> takeWhile1 (\c -> c == '_' || c == ':' || isAlphaNum c)

hexBsParser :: Parser ByteString
hexBsParser = do
  void $ string "hex:"
  either (fail . unpack) pure . decodeHex . encodeUtf8 =<< takeWhile1 (inClass "0-9a-fA-F")

rfc3339DateParser :: Parser UTCTime
rfc3339DateParser =
  let getDateInput = takeWhile1 (notInClass ", )];")
      parseDate = parseTimeM False defaultTimeLocale "%FT%T%Q%EZ"
  in parseDate . unpack =<< getDateInput

litStringParser :: Parser Text
litStringParser =
  let regularChars = takeTill (inClass "\"\\")
      escaped = choice
        [ string "\\n" $> "\n"
        , string "\\\"" $> "\""
        , string "\\\\"  $> "\\"
        ]
      str = do
        f <- regularChars
        r <- optional (liftA2 (<>) escaped str)
        pure $ f <> F.fold r
  in char '"' *> str <* char '"'

delimited :: Parser x -> Parser y -> Parser a -> Parser a
delimited before after p = before *> p <* after

parens :: Parser a -> Parser a
parens = delimited (char '(') (skipSpace *> char ')')

predicateNameParser :: Parser Text
predicateNameParser = do
  first <- satisfy isLetter
  rest  <- A.takeWhile $ \c -> c == '_' || c == ':' || isAlphaNum c
  pure $ T.singleton first <> rest

ruleHeadParser :: HasParsers 'InPredicate ctx => Parser (Predicate' 'InPredicate ctx)
ruleHeadParser = do
  skipSpace
  name <- predicateNameParser
  skipSpace
  terms <- parens (commaList0 termParser)
  pure Predicate{name,terms}

binary :: Text -> Binary -> Expr.Operator Parser (Expression' ctx)
binary name op = Expr.InfixL  (EBinary op <$ (skipSpace *> string name))

table :: [[Expr.Operator Parser (Expression' ctx)]]
table = [ [ binary  "*" Mul
          , binary  "/" Div
          ]
        , [ binary  "+" Add
          , binary  "-" Sub
          ]
        , [ binary  "<=" LessOrEqual
          , binary  ">=" GreaterOrEqual
          , binary  "<"  LessThan
          , binary  ">"  GreaterThan
          , binary  "==" Equal
          ]
        , [ binary  "&&" And
          , binary  "||" Or
          ]
        ]

methodParser :: HasParsers 'InPredicate ctx => Parser (Expression' ctx)
methodParser = do
  e1 <- exprTerm
  _ <- char '.'
  method <- choice
    [ Contains     <$ string "contains"
    , Intersection <$ string "intersection"
    , Union        <$ string "union"
    , Prefix       <$ string "starts_with"
    , Suffix       <$ string "ends_with"
    , Regex        <$ string "matches"
    ]
  _ <- char '('
  skipSpace
  e2 <- expressionParser
  skipSpace
  _ <- char ')'
  pure $ EBinary method e1 e2

expressionParser :: HasParsers 'InPredicate ctx => Parser (Expression' ctx)
expressionParser = Expr.makeExprParser (methodParser <|> exprTerm) table

unaryParens :: HasParsers 'InPredicate ctx => Parser (Expression' ctx)
unaryParens = do
  skipSpace
  _ <- char '('
  skipSpace
  e <- expressionParser
  skipSpace
  _ <- char ')'
  pure $ EUnary Parens e

unaryNegate :: HasParsers 'InPredicate ctx => Parser (Expression' ctx)
unaryNegate = do
  skipSpace
  _ <- char '!'
  skipSpace
  EUnary Negate <$> expressionParser

unaryLength :: HasParsers 'InPredicate ctx => Parser (Expression' ctx)
unaryLength = do
  skipSpace
  e <- choice
          [ EValue <$> termParser
          , unaryParens
          ]
  skipSpace
  _ <- string ".length()"
  pure $ EUnary Length e

unary :: HasParsers 'InPredicate ctx => Parser (Expression' ctx)
unary = choice
  [ unaryParens
  , unaryNegate
  , unaryLength
  ]

exprTerm :: HasParsers 'InPredicate ctx => Parser (Expression' ctx)
exprTerm = choice
  [ unary
  , EValue <$> termParser
  ]

commaList :: Parser a -> Parser [a]
commaList p = sepBy1 p (skipSpace *> char ',')

predicateParser :: HasParsers pof ctx => Parser (Predicate' pof ctx)
predicateParser = do
  skipSpace
  name <- predicateNameParser
  skipSpace
  terms <- parens (commaList termParser)
  pure Predicate{name,terms}

ruleBodyParser :: HasParsers 'InPredicate ctx => Parser ([Predicate' 'InPredicate ctx], [Expression' ctx])
ruleBodyParser = do
  let predicateOrExprParser = Right <$> expressionParser <|> Left <$> predicateParser
  els <- sepBy1 (skipSpace *> predicateOrExprParser) (skipSpace *> char ',')
  pure $ partitionEithers els

ruleParser :: HasParsers 'InPredicate ctx => Parser (Rule' ctx)
ruleParser = do
  rhead <- ruleHeadParser
  skipSpace
  void $ string "<-"
  (body, expressions) <- ruleBodyParser
  pure Rule{rhead, body, expressions, scope = Nothing}

queryParser :: HasParsers 'InPredicate ctx => Parser (Query' ctx)
queryParser =
  let mkQueryItem (qBody, qExpressions) = QueryItem { qBody, qExpressions, qScope = Nothing }
  in fmap mkQueryItem <$> sepBy1 ruleBodyParser (skipSpace *> asciiCI "or" <* satisfy isSpace)

checkParser :: HasParsers 'InPredicate ctx => Parser (Check' ctx)
checkParser = string "check if" *> queryParser

commentParser :: Parser ()
commentParser = do
  skipSpace
  _ <- string "//"
  _ <- skipWhile ((&&) <$> (/= '\r') <*> (/= '\n'))
  void $ choice [ void (char '\n')
                , void (string "\r\n")
                , endOfInput
                ]
blockElementParser :: HasParsers 'InPredicate ctx => Parser (BlockElement' ctx)
blockElementParser = choice
  [ BlockRule    <$> ruleParser <* skipSpace <* char ';'
  , BlockFact    <$> predicateParser <* skipSpace <* char ';'
  , BlockCheck   <$> checkParser <* skipSpace <* char ';'
  , BlockComment <$  commentParser
  ]

blockParser :: (HasParsers 'InPredicate ctx) => Parser (Block' ctx)
blockParser = do
  els <- many' (skipSpace *> blockElementParser)
  pure $ foldMap elementToBlock els

compileParser :: Lift a => Parser a -> String -> Q Exp
compileParser p str =
  case parseOnly (p <* skipSpace <* endOfInput) (pack str) of
    Right result -> [| result |]
    Left e       -> fail e

policyParser :: HasParsers 'InPredicate ctx => Parser (Policy' ctx)
policyParser = do
  policy <- choice
              [ Allow <$ string "allow if"
              , Deny  <$ string "deny if"
              ]
  (policy, ) <$> queryParser

authorizerElementParser :: HasParsers 'InPredicate ctx => Parser (AuthorizerElement' ctx)
authorizerElementParser = choice
  [ AuthorizerPolicy  <$> policyParser <* skipSpace <* char ';'
  , BlockElement    <$> blockElementParser
  ]

authorizerParser :: HasParsers 'InPredicate ctx => Parser (Authorizer' ctx)
authorizerParser = do
  els <- many' (skipSpace *> authorizerElementParser)
  pure $ foldMap elementToAuthorizer els

authorizer :: QuasiQuoter
authorizer = QuasiQuoter
  { quoteExp = compileParser (authorizerParser @'QuasiQuote)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

block :: QuasiQuoter
block = QuasiQuoter
  { quoteExp = compileParser (blockParser @'QuasiQuote)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

check :: QuasiQuoter
check = QuasiQuoter
  { quoteExp = compileParser (checkParser @'QuasiQuote)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

fact :: QuasiQuoter
fact = QuasiQuoter
  { quoteExp = compileParser (predicateParser @'InFact @'QuasiQuote)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

predicate :: QuasiQuoter
predicate = QuasiQuoter
  { quoteExp = compileParser (predicateParser @'InPredicate @'QuasiQuote)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

rule :: QuasiQuoter
rule = QuasiQuoter
  { quoteExp = compileParser (ruleParser @'QuasiQuote)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

query :: QuasiQuoter
query = QuasiQuoter
  { quoteExp = compileParser (queryParser @'QuasiQuote)
  , quotePat = error "not supported"
  , quoteType = error "not supported"
  , quoteDec = error "not supported"
  }

class ConditionalParse a v
  where
    ifPresent :: String -> Parser a -> Parser v

instance ConditionalParse a Void
  where
    ifPresent name _ = fail $ name <> " is not available in this context"

instance ConditionalParse m m
  where
    ifPresent _ p = p

class SetParser (inSet :: IsWithinSet) (ctx :: ParsedAs)
  where
    parseSet :: Parser (SetType inSet ctx)

instance SetParser 'WithinSet ctx
  where
    parseSet = fail "nested sets are forbidden"

instance SetParser 'NotWithinSet 'QuasiQuote
  where
    parseSet = Set.fromList <$> (char '[' *> commaList0 termParser <* char ']')

instance SetParser 'NotWithinSet 'RegularString
  where
    parseSet = Set.fromList <$> (char '[' *> commaList0 termParser <* char ']')
