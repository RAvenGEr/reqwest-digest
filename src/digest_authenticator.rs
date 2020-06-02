use digest::Digest;
use http::header::WWW_AUTHENTICATE;
use http::HeaderMap;
use md5::Md5;
use rand::distributions::{Distribution, Uniform};
use rand::thread_rng;
use sha2::Sha256;
use std::fmt;

#[derive(Debug, PartialEq)]
enum DigestAlgorithm {
    MD5,
    SHA256,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum QualityOfProtection {
    None,
    Auth,
    AuthInt,
}

impl QualityOfProtection {
    fn to_str(self: Self) -> &'static str {
        match self {
            QualityOfProtection::Auth => "auth",
            QualityOfProtection::AuthInt => "auth-int",
            QualityOfProtection::None => "",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    kind: ParseErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseErrorKind {
    Empty,
    MissingDigest,
    MissingRealm,
    MissingNonce,
}

impl ParseError {
    fn description(&self) -> &str {
        match self.kind {
            ParseErrorKind::Empty => "cannot parse Digest scheme from empty string",
            ParseErrorKind::MissingDigest => "string does not start with \"Digest \"",
            ParseErrorKind::MissingNonce => "Digest scheme must contain a nonce value",
            ParseErrorKind::MissingRealm => "Digest scheme must contain a realm value",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.description().fmt(f)
    }
}

#[derive(Debug)]
pub struct DigestScheme<'a> {
    nonce: &'a str,
    domain: Option<Vec<&'a str>>,
    realm: &'a str,
    opaque: Option<&'a str>,
    stale: bool,
    cnonce: Option<String>,
    nonce_count: u32,
    algorithm: DigestAlgorithm,
    session: bool,
    qop: QualityOfProtection,
}

impl<'a> DigestScheme<'a> {
    pub fn www_authenticate_string(headers: &HeaderMap) -> Option<String> {
        if let Ok(a) = headers.get(WWW_AUTHENTICATE)?.to_str() {
            if &a[..7].to_lowercase() == "digest " {
                return Some(a.to_string());
            }
        }
        None
    }

    pub fn parse_authenticate_str(auth: &'a str) -> Result<Self, ParseError> {
        if auth.is_empty() {
            return Err(ParseError {
                kind: ParseErrorKind::Empty,
            });
        }

        if &auth[..7].to_lowercase() != "digest " {
            return Err(ParseError {
                kind: ParseErrorKind::MissingDigest,
            });
        }
        let mut maybe_nonce: Option<&str> = None;
        let mut domain: Option<Vec<&str>> = None;
        let mut maybe_realm: Option<&str> = None;
                let mut opaque: Option<&str> = None;
                let mut stale = false;
                let mut algorithm = DigestAlgorithm::MD5;
        let mut session = false;
                let mut qop = QualityOfProtection::None;

        enum KeyVal {
            Key,
            Val,
        }

        let mut state = KeyVal::Key;
        let mut key: String = "".to_owned();
        let mut key_start = 7;
        let mut val_start = 0;
        for ch_ind in auth[7..].char_indices() {
            match state {
                KeyVal::Key => {
                    if ch_ind.1 != '=' {
                        continue;
                    }
                    // ignore '='
                    key = auth[key_start..ch_ind.0 + 7].trim().to_lowercase();
                    val_start = ch_ind.0 + 8;
                    state = KeyVal::Val;
                }
                KeyVal::Val => {
                    if ch_ind.0 != auth.len() - 1 && ch_ind.1 != ',' {
                        continue;
                    }
                    let val = auth[val_start..ch_ind.0 + 7].trim().trim_matches('"');
                        if key == "nonce" {
                        maybe_nonce = Some(val);
                        } else if key == "realm" {
                        maybe_realm = Some(val);
                        } else if key == "domain" {
                        domain = Some(val.split(' ').collect());
                        } else if key == "opaque" {
                            opaque = Some(val);
                        } else if key == "stale" && val.to_lowercase() == "true" {
                            stale = true;
                        } else if key == "algorithm" {
                            let alg_str = val.to_lowercase();
                            if alg_str == "md5-sess" {
                            session = true;
                        } else if alg_str == "sha-256" {
                            algorithm = DigestAlgorithm::SHA256;
                        } else if alg_str == "sha-256-sess" {
                            algorithm = DigestAlgorithm::SHA256;
                            session = true;
                            }
                        } else if key == "qop" {
                            let qop_str = val.to_lowercase();
                        if qop_str == QualityOfProtection::AuthInt.to_str() {
                                qop = QualityOfProtection::AuthInt;
                            } else {
                                qop = QualityOfProtection::Auth;
                            }
                        }
                    // ignore ','
                    state = KeyVal::Key;
                    key_start = ch_ind.0 + 8;
                    }
                }
        }
        match (maybe_nonce, maybe_realm) {
            (Some(nonce), Some(realm)) => Ok(Self {
                nonce,
                        domain,
                realm,
                        opaque,
                        stale,
                cnonce: None,
                        algorithm,
                session,
                        qop,
                nonce_count: 0,
            }),
            (Some(_), None) => Err(ParseError {
                kind: ParseErrorKind::MissingRealm,
            }),
            (None, Some(_)) => Err(ParseError {
                kind: ParseErrorKind::MissingNonce,
            }),
            (None, None) => Err(ParseError {
                kind: ParseErrorKind::MissingNonce,
            }),
                }
            }

    pub fn generate_auth_string(
        self: &mut Self,
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> String {
        self.cnonce = Some(Self::cnonce());
        self.nonce_count += 1;
        let count_str = format!("{:08.x}", self.nonce_count);
        let qop = if self.qop == QualityOfProtection::AuthInt && body.is_none() {
            QualityOfProtection::Auth
        } else {
            self.qop
        };
        let response = match self.algorithm {
            DigestAlgorithm::MD5 => self.generate_response_string::<Md5>(
                username, password, method, uri, &count_str, body, qop,
            ),
            DigestAlgorithm::SHA256 => self.generate_response_string::<Sha256>(
                username, password, method, uri, &count_str, body, qop,
            ),
        };
        let cnonce = self.cnonce.as_ref().unwrap();
        let qop_str = qop.to_str();
        let mut auth_str_len = 90
            + username.len()
            + self.realm.len()
            + self.nonce.len()
            + uri.len()
            + count_str.len()
            + cnonce.len()
            + response.len()
            + qop_str.len();
        if self.qop != QualityOfProtection::None {
            auth_str_len += 6;
        }
        if let Some(o) = self.opaque {
            auth_str_len += 11 + o.len();
        }
        let mut auth = String::with_capacity(auth_str_len);
        auth.push_str("Digest username=\"");
        auth.push_str(username);
        auth.push_str("\", realm=\"");
        auth.push_str(self.realm);
        auth.push_str("\", nonce=\"");
        auth.push_str(self.nonce);
        auth.push_str("\", uri=\"");
        auth.push_str(uri);
        if self.qop != QualityOfProtection::None {
            auth.push_str("\", qop=");
            auth.push_str(qop_str);
        } else {
            auth.push('"');
        }
        auth.push_str(", algorithm=MD5, nc=");
        auth.push_str(&count_str);
        auth.push_str(", cnonce=\"");
        auth.push_str(cnonce);
        auth.push_str("\", response=\"");
        auth.push_str(&response);
        if let Some(o) = self.opaque {
            auth.push_str("\", opaque=\"");
            auth.push_str(o);
        }
        auth.push('"');
        auth
    }

    fn cnonce() -> String {
        let mut rng = thread_rng();
        let len = Uniform::new_inclusive(8, 32);
        let val = Uniform::new_inclusive(0, 15);
        let mut cnonce = String::with_capacity(len.sample(&mut rng));
        let hex_vals = [
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        ];
        while cnonce.len() < cnonce.capacity() {
            cnonce.push(hex_vals[val.sample(&mut rng)]);
        }
        cnonce
    }

    fn calculate_ha1<T: Digest>(self: &Self, username: &str, password: &str) -> String {
        let mut hasher = T::new();
        hasher.input(username);
        hasher.input(":");
        hasher.input(self.realm);
        hasher.input(":");
        hasher.input(password);
        let mut digest = hasher.result();
        if self.session {
            let cnonce = self.cnonce.as_ref().unwrap();
            hasher = T::new();
            hasher.input(digest);
            hasher.input(":");
            hasher.input(self.nonce);
            hasher.input(":");
            hasher.input(cnonce);
            digest = hasher.result();
        }
        hex::encode(digest)
    }

    fn calculate_ha2<T: Digest>(
        self: &Self,
        method: &str,
        uri: &str,
        body: Option<&str>,
        qop: QualityOfProtection,
    ) -> String {
        let mut hasher = T::new();
        hasher.input(method);
        hasher.input(":");
        hasher.input(uri);
        if qop == QualityOfProtection::AuthInt {
            hasher.input(":");
            hasher.input(body.unwrap());
        }
        let digest = hasher.result();
        hex::encode(digest)
    }

    fn calculate_response<T: Digest>(
        self: &Self,
        ha1: &str,
        ha2: &str,
        nonce_count_str: &str,
    ) -> String {
        let mut hasher = T::new();
        hasher.input(ha1);
        hasher.input(":");
        hasher.input(self.nonce);
        hasher.input(":");
        if self.qop != QualityOfProtection::None {
            let cnonce = self.cnonce.as_ref().unwrap();
            hasher.input(nonce_count_str);
            hasher.input(":");
            hasher.input(cnonce);
            hasher.input(":");
            hasher.input(self.qop.to_str());
            hasher.input(":");
        }
        hasher.input(ha2);
        let digest = hasher.result();
        hex::encode(digest)
    }

    fn generate_response_string<T: Digest>(
        self: &Self,
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        count_str: &str,
        body: Option<&str>,
        qop: QualityOfProtection,
    ) -> String {
        let ha1 = self.calculate_ha1::<T>(username, password);

        let ha2 = self.calculate_ha2::<T>(method, uri, body, qop);

        self.calculate_response::<T>(&ha1, &ha2, &count_str)
    }
}
