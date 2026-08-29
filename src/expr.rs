//! The tt++ expression language, used by #math, #if, #elseif, #while,
//! #switch/#case, and %m in #format.
//!
//! C-like precedence per the tt++ manual: unary `! ~ -`, dice `d`, then
//! `* ** / // %`, `+ -`, `<< >>`, comparisons, `== != === !==`, `& ^ |`,
//! `&& ^^ ||`, and `?:` ternary. `==`/`!=` on strings do tt++ pattern
//! matching (with {a|b} alternation); `===`/`!==` compare exactly.
//! True is non-zero.

use crate::pattern;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Float(f64),
    Str(String),
}

impl Value {
    pub fn truthy(&self) -> bool {
        match self {
            Value::Int(i) => *i != 0,
            Value::Float(f) => *f != 0.0,
            Value::Str(s) => !s.is_empty(),
        }
    }

    fn as_f64(&self) -> f64 {
        match self {
            Value::Int(i) => *i as f64,
            Value::Float(f) => *f,
            Value::Str(s) => s.trim().parse().unwrap_or(0.0),
        }
    }

    fn as_i64(&self) -> i64 {
        match self {
            Value::Int(i) => *i,
            Value::Float(f) => *f as i64,
            Value::Str(s) => s.trim().parse().unwrap_or(0),
        }
    }

    pub fn display(&self) -> String {
        match self {
            Value::Int(i) => i.to_string(),
            Value::Float(f) => {
                if f.fract() == 0.0 && f.abs() < 1e15 {
                    format!("{:.2}", f)
                } else {
                    format!("{}", f)
                }
            }
            Value::Str(s) => s.clone(),
        }
    }
}

fn num(f: f64, force_float: bool) -> Value {
    if !force_float && f.fract() == 0.0 && f.abs() < 9e15 {
        Value::Int(f as i64)
    } else {
        Value::Float(f)
    }
}

fn bool_val(b: bool) -> Value {
    Value::Int(if b { 1 } else { 0 })
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64, bool), // value, had decimal point
    Str(String),
    Op(&'static str),
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Result<Vec<Tok>, String> {
    let mut toks = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' => {
                chars.next();
            }
            '(' => {
                chars.next();
                toks.push(Tok::LParen);
            }
            ')' => {
                chars.next();
                toks.push(Tok::RParen);
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                for n in chars.by_ref() {
                    if n == '"' {
                        break;
                    }
                    s.push(n);
                }
                toks.push(Tok::Str(s));
            }
            '{' => {
                chars.next();
                let mut s = String::new();
                let mut depth = 1;
                for n in chars.by_ref() {
                    match n {
                        '{' => depth += 1,
                        '}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    s.push(n);
                }
                toks.push(Tok::Str(s));
            }
            '0'..='9' | '.' => {
                let mut s = String::new();
                let mut float = false;
                while let Some(&n) = chars.peek() {
                    if n.is_ascii_digit() {
                        s.push(n);
                        chars.next();
                    } else if n == '.' && !float {
                        // ".." is the range operator, not a decimal point
                        let mut ahead = chars.clone();
                        ahead.next();
                        if ahead.peek() == Some(&'.') {
                            break;
                        }
                        float = true;
                        s.push(n);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if s == "." {
                    return Err("stray '.'".into());
                }
                let v: f64 = s.parse().map_err(|_| format!("bad number '{}'", s))?;
                toks.push(Tok::Num(v, float));
            }
            'd' => {
                // dice operator when between numbers: 2d6
                chars.next();
                toks.push(Tok::Op("d"));
            }
            _ => {
                chars.next();
                let two = |second: char, a: &'static str, b: &'static str, chars: &mut std::iter::Peekable<std::str::Chars<'_>>| {
                    if chars.peek() == Some(&second) {
                        chars.next();
                        a
                    } else {
                        b
                    }
                };
                let op: &'static str = match c {
                    '!' => {
                        if chars.peek() == Some(&'=') {
                            chars.next();
                            if chars.peek() == Some(&'=') {
                                chars.next();
                                "!=="
                            } else {
                                "!="
                            }
                        } else {
                            "!"
                        }
                    }
                    '=' => {
                        if chars.peek() == Some(&'=') {
                            chars.next();
                            if chars.peek() == Some(&'=') {
                                chars.next();
                                "==="
                            } else {
                                "=="
                            }
                        } else {
                            return Err("single '=' is not an operator (use ==)".into());
                        }
                    }
                    '*' => two('*', "**", "*", &mut chars),
                    '/' => two('/', "//", "/", &mut chars),
                    '%' => "%",
                    '+' => "+",
                    '-' => "-",
                    '~' => "~",
                    '<' => {
                        if chars.peek() == Some(&'<') {
                            chars.next();
                            "<<"
                        } else {
                            two('=', "<=", "<", &mut chars)
                        }
                    }
                    '>' => {
                        if chars.peek() == Some(&'>') {
                            chars.next();
                            ">>"
                        } else {
                            two('=', ">=", ">", &mut chars)
                        }
                    }
                    '&' => two('&', "&&", "&", &mut chars),
                    '|' => two('|', "||", "|", &mut chars),
                    '^' => two('^', "^^", "^", &mut chars),
                    '?' => "?",
                    ':' => ":",
                    other => return Err(format!("unexpected '{}' in expression", other)),
                };
                toks.push(Tok::Op(op));
            }
        }
    }
    Ok(toks)
}

struct Parser<'a> {
    toks: &'a [Tok],
    pos: usize,
    rng: u64,
}

pub fn eval(input: &str) -> Result<Value, String> {
    let toks = tokenize(input)?;
    if toks.is_empty() {
        return Ok(Value::Int(0));
    }
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64 ^ d.as_secs())
        .unwrap_or(0x9e3779b9)
        | 1;
    let mut p = Parser { toks: &toks, pos: 0, rng: seed };
    let v = p.ternary()?;
    if p.pos != p.toks.len() {
        return Err("trailing junk in expression".into());
    }
    Ok(v)
}

impl<'a> Parser<'a> {
    fn peek_op(&self) -> Option<&'static str> {
        match self.toks.get(self.pos) {
            Some(Tok::Op(o)) => Some(o),
            _ => None,
        }
    }

    fn roll(&mut self, sides: i64) -> i64 {
        // xorshift64
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng = x;
        if sides <= 1 {
            return sides.max(1);
        }
        (x % sides as u64) as i64 + 1
    }

    fn ternary(&mut self) -> Result<Value, String> {
        let cond = self.binary(12)?;
        if self.peek_op() == Some("?") {
            self.pos += 1;
            let t = self.ternary()?;
            if self.peek_op() != Some(":") {
                return Err("'?' without ':'".into());
            }
            self.pos += 1;
            let f = self.ternary()?;
            return Ok(if cond.truthy() { t } else { f });
        }
        Ok(cond)
    }

    fn binary(&mut self, level: i32) -> Result<Value, String> {
        if level < 1 {
            return self.unary();
        }
        let ops: &[&str] = match level {
            1 => &["d"],
            2 => &["**", "*", "//", "/", "%"],
            3 => &["+", "-"],
            4 => &["<<", ">>"],
            5 => &[">=", "<=", ">", "<"],
            6 => &["===", "!==", "==", "!="],
            7 => &["&"],
            8 => &["^"],
            9 => &["|"],
            10 => &["&&"],
            11 => &["^^"],
            12 => &["||"],
            _ => &[],
        };
        let mut lhs = self.binary(level - 1)?;
        while let Some(op) = self.peek_op() {
            if !ops.contains(&op) {
                break;
            }
            self.pos += 1;
            let rhs = self.binary(level - 1)?;
            lhs = self.apply(op, lhs, rhs)?;
        }
        Ok(lhs)
    }

    fn unary(&mut self) -> Result<Value, String> {
        match self.toks.get(self.pos) {
            Some(Tok::Op("!")) => {
                self.pos += 1;
                let v = self.unary()?;
                Ok(bool_val(!v.truthy()))
            }
            Some(Tok::Op("~")) => {
                self.pos += 1;
                let v = self.unary()?;
                Ok(Value::Int(!v.as_i64()))
            }
            Some(Tok::Op("-")) => {
                self.pos += 1;
                let v = self.unary()?;
                Ok(match v {
                    Value::Int(i) => Value::Int(-i),
                    Value::Float(f) => Value::Float(-f),
                    Value::Str(s) => Value::Float(-s.trim().parse::<f64>().unwrap_or(0.0)),
                })
            }
            Some(Tok::Op("+")) => {
                self.pos += 1;
                self.unary()
            }
            Some(Tok::LParen) => {
                self.pos += 1;
                let v = self.ternary()?;
                if self.toks.get(self.pos) != Some(&Tok::RParen) {
                    return Err("missing ')'".into());
                }
                self.pos += 1;
                Ok(v)
            }
            Some(Tok::Num(v, float)) => {
                let (v, float) = (*v, *float);
                self.pos += 1;
                Ok(num(v, float))
            }
            Some(Tok::Str(s)) => {
                let s = s.clone();
                self.pos += 1;
                Ok(Value::Str(s))
            }
            _ => Err("expected a value".into()),
        }
    }

    fn apply(&mut self, op: &str, lhs: Value, rhs: Value) -> Result<Value, String> {
        let float = matches!(lhs, Value::Float(_)) || matches!(rhs, Value::Float(_));
        Ok(match op {
            "d" => {
                let (n, sides) = (lhs.as_i64().clamp(0, 1000), rhs.as_i64());
                let mut total = 0;
                for _ in 0..n {
                    total += self.roll(sides);
                }
                Value::Int(total)
            }
            "+" => num(lhs.as_f64() + rhs.as_f64(), float),
            "-" => num(lhs.as_f64() - rhs.as_f64(), float),
            "*" => num(lhs.as_f64() * rhs.as_f64(), float),
            "**" => num(lhs.as_f64().powf(rhs.as_f64()), float),
            "/" => {
                let d = rhs.as_f64();
                if d == 0.0 {
                    return Err("division by zero".into());
                }
                if float {
                    Value::Float(lhs.as_f64() / d)
                } else {
                    Value::Int(lhs.as_i64() / rhs.as_i64())
                }
            }
            "//" => {
                // tt++ root operator: a // b is the b-th root of a
                let r = rhs.as_f64();
                if r == 0.0 {
                    return Err("zeroth root".into());
                }
                num(lhs.as_f64().powf(1.0 / r), float)
            }
            "%" => {
                let d = rhs.as_i64();
                if d == 0 {
                    return Err("modulo by zero".into());
                }
                Value::Int(lhs.as_i64() % d)
            }
            "<<" => Value::Int(lhs.as_i64() << (rhs.as_i64() & 63)),
            ">>" => Value::Int(lhs.as_i64() >> (rhs.as_i64() & 63)),
            "&" => Value::Int(lhs.as_i64() & rhs.as_i64()),
            "^" => Value::Int(lhs.as_i64() ^ rhs.as_i64()),
            "|" => Value::Int(lhs.as_i64() | rhs.as_i64()),
            "&&" => bool_val(lhs.truthy() && rhs.truthy()),
            "||" => bool_val(lhs.truthy() || rhs.truthy()),
            "^^" => bool_val(lhs.truthy() ^ rhs.truthy()),
            ">" | ">=" | "<" | "<=" => {
                let ord = match (&lhs, &rhs) {
                    (Value::Str(a), Value::Str(b)) => a.cmp(b),
                    _ => lhs
                        .as_f64()
                        .partial_cmp(&rhs.as_f64())
                        .ok_or("unordered comparison")?,
                };
                bool_val(match op {
                    ">" => ord.is_gt(),
                    ">=" => ord.is_ge(),
                    "<" => ord.is_lt(),
                    _ => ord.is_le(),
                })
            }
            "==" | "!=" => {
                let eq = match (&lhs, &rhs) {
                    (Value::Str(a), Value::Str(b)) => pattern::matches_full(b, a),
                    (Value::Str(a), b) => pattern::matches_full(&b.display(), a),
                    (a, Value::Str(b)) => pattern::matches_full(b, &a.display()),
                    _ => lhs.as_f64() == rhs.as_f64(),
                };
                bool_val(if op == "==" { eq } else { !eq })
            }
            "===" | "!==" => {
                let eq = match (&lhs, &rhs) {
                    (Value::Str(a), Value::Str(b)) => a == b,
                    _ => lhs.as_f64() == rhs.as_f64(),
                };
                bool_val(if op == "===" { eq } else { !eq })
            }
            other => return Err(format!("unhandled operator {}", other)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(e: &str) -> Value {
        eval(e).unwrap()
    }

    #[test]
    fn arithmetic_and_precedence() {
        assert_eq!(n("1 + 2 * 3"), Value::Int(7));
        assert_eq!(n("(1 + 2) * 3"), Value::Int(9));
        assert_eq!(n("10 / 4"), Value::Int(2));
        assert_eq!(n("10.0 / 4"), Value::Float(2.5));
        assert_eq!(n("2 ** 10"), Value::Int(1024));
        assert_eq!(n("27 // 3"), Value::Int(3));
        assert_eq!(n("7 % 3"), Value::Int(1));
        assert_eq!(n("-5 + 2"), Value::Int(-3));
    }

    #[test]
    fn comparisons_and_logic() {
        assert_eq!(n("5 > 3"), Value::Int(1));
        assert_eq!(n("5 > 3 && 2 < 1"), Value::Int(0));
        assert_eq!(n("5 > 3 || 2 < 1"), Value::Int(1));
        assert_eq!(n("!0"), Value::Int(1));
        assert_eq!(n("1 << 4"), Value::Int(16));
        assert_eq!(n("6 & 3"), Value::Int(2));
    }

    #[test]
    fn ternary() {
        assert_eq!(n("1 ? 10 : 20"), Value::Int(10));
        assert_eq!(n("0 ? 10 : 20"), Value::Int(20));
        assert_eq!(n("5 > 3 ? 1 + 1 : 9"), Value::Int(2));
    }

    #[test]
    fn strings_pattern_vs_exact() {
        assert_eq!(n("\"bla\" == \"{bli|bla}\""), Value::Int(1));
        assert_eq!(n("\"blub\" == \"{bli|bla}\""), Value::Int(0));
        assert_eq!(n("\"abc\" === \"abc\""), Value::Int(1));
        assert_eq!(n("\"abc\" === \"a%*\""), Value::Int(0));
        assert_eq!(n("\"abc\" == \"a%*\""), Value::Int(1));
        assert_eq!(n("\"\" == \"\""), Value::Int(1));
        assert_eq!(n("{abc} != {xyz}"), Value::Int(1));
    }

    #[test]
    fn dice() {
        for _ in 0..20 {
            let v = n("3d6").as_i64();
            assert!((3..=18).contains(&v), "3d6 rolled {}", v);
        }
        assert_eq!(n("0d6"), Value::Int(0));
    }

    #[test]
    fn division_by_zero_errors() {
        assert!(eval("1 / 0").is_err());
        assert!(eval("1 % 0").is_err());
    }
}
