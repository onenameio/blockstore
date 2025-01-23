use std::fmt::Display;

use crate::vm::representations::Span;

#[derive(Debug, PartialEq, Clone)]
pub enum Token {
    Eof,
    Whitespace,
    Lparen,
    Rparen,
    Lbrace,
    Rbrace,
    Colon,
    Comma,
    Dot,
    Int(String),
    Uint(String),
    AsciiString(String),
    Utf8String(String),
    Bytes(String),
    Principal(String),
    Ident(String),
    TraitIdent(String),
    Plus,
    Minus,
    Multiply,
    Divide,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Comment(String),
    Placeholder(String), // used to continue parsing after errors
}

#[derive(Clone, Debug)]
pub struct PlacedToken {
    pub span: Span,
    pub token: Token,
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use self::Token::*;
        match self {
            Eof => write!(f, "EOF"),
            Whitespace => write!(f, "whitespace"),
            Lparen => write!(f, "("),
            Rparen => write!(f, ")"),
            Lbrace => write!(f, "{{"),
            Rbrace => write!(f, "}}"),
            Colon => write!(f, ":"),
            Comma => write!(f, ","),
            Dot => write!(f, "."),
            Int(_) => write!(f, "int"),
            Uint(_) => write!(f, "uint"),
            AsciiString(_) => write!(f, "string-ascii"),
            Utf8String(_) => write!(f, "string-utf8"),
            Bytes(_) => write!(f, "bytes"),
            Principal(_) => write!(f, "principal"),
            Ident(_) => write!(f, "identifier"),
            TraitIdent(_) => write!(f, "trait-identifier"),
            Plus => write!(f, "+"),
            Minus => write!(f, "-"),
            Multiply => write!(f, "*"),
            Divide => write!(f, "/"),
            Less => write!(f, "<"),
            LessEqual => write!(f, "<="),
            Greater => write!(f, ">"),
            GreaterEqual => write!(f, ">="),
            Comment(_) => write!(f, "comment"),
            Placeholder(_) => write!(f, "placeholder"),
        }
    }
}

impl Token {
    pub fn reproduce(&self) -> String {
        use self::Token::*;
        match self {
            Eof => "".to_string(),
            Whitespace => " ".to_string(),
            Lparen => "(".to_string(),
            Rparen => ")".to_string(),
            Lbrace => "{{".to_string(),
            Rbrace => "}}".to_string(),
            Colon => ":".to_string(),
            Comma => ",".to_string(),
            Dot => ".".to_string(),
            Int(s) => s.to_string(),
            Uint(s) => format!("u{}", s),
            AsciiString(s) => format!("\"{}\"", s),
            Utf8String(s) => s.to_string(),
            Bytes(s) => format!("0x{}", s),
            Principal(s) => format!("'{}", s),
            Ident(s) => s.to_string(),
            TraitIdent(s) => format!("<{}>", s),
            Plus => "+".to_string(),
            Minus => "-".to_string(),
            Multiply => "*".to_string(),
            Divide => "/".to_string(),
            Less => "<".to_string(),
            LessEqual => "<=".to_string(),
            Greater => ">".to_string(),
            GreaterEqual => ">=".to_string(),
            Comment(c) => format!(";; {}", c),
            Placeholder(s) => s.to_string(),
        }
    }
}
