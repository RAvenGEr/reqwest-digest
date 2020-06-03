use digest::Digest;
use http::header::WWW_AUTHENTICATE;
use http::HeaderMap;
use md5::Md5;
use rand::distributions::{Distribution, Uniform};
use rand::thread_rng;
use regex::Regex;
use sha2::Sha256;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
enum DigestAlgorithm {
    MD5,
    SHA256,
}

impl DigestAlgorithm {
    fn to_str(&self) -> &'static str {
        match self {
            DigestAlgorithm::MD5 => "MD5",
            DigestAlgorithm::SHA256 => "SHA-256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum QualityOfProtection {
    None, // rfc2069
    Auth,
    AuthInt,
}

impl QualityOfProtection {
    fn to_str(&self) -> &'static str {
        match self {
            QualityOfProtection::Auth => "auth",
            QualityOfProtection::AuthInt => "auth-int",
            QualityOfProtection::None => "",
        }
    }
}

#[derive(Debug)]
struct QualityOfProtectionData {
    cnonce: String,
    count_str: String,
    qop: QualityOfProtection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestParseError {
    kind: DigestParseErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestParseErrorKind {
    Empty,
    MissingDigest,
    MissingRealm,
    MissingNonce,
}

impl DigestParseError {
    fn new(kind: DigestParseErrorKind) -> Self {
        Self { kind }
    }
    fn description(&self) -> &str {
        match self.kind {
            DigestParseErrorKind::Empty => "cannot parse Digest scheme from empty string",
            DigestParseErrorKind::MissingDigest => "string does not start with \"Digest \"",
            DigestParseErrorKind::MissingNonce => "Digest scheme must contain a nonce value",
            DigestParseErrorKind::MissingRealm => "Digest scheme must contain a realm value",
        }
    }
}

impl fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.description().fmt(f)
    }
}

#[derive(Debug, Default)]
struct StrPosition {
    start: usize,
    end: usize,
}

impl StrPosition {
    fn to_str<'a>(&self, s: &'a str) -> &'a str {
        &s[self.start..self.end]
    }

    fn is_valid(&self) -> bool {
        self.start < self.end
    }
}

#[derive(Debug)]
pub struct DigestScheme {
    www_authenticate: String,
    nonce: StrPosition,
    domain: Option<Vec<StrPosition>>,
    realm: StrPosition,
    opaque: StrPosition,
    stale: bool,
    nonce_count: u32,
    algorithm: DigestAlgorithm,
    session: bool,
    userhash: bool,
    qop: QualityOfProtection,
    qop_data: Option<QualityOfProtectionData>,
}

impl FromStr for DigestScheme {
    type Err = DigestParseError;

    fn from_str(auth: &str) -> Result<Self, Self::Err> {
        if auth.is_empty() {
            return Err(DigestParseError::new(DigestParseErrorKind::Empty));
        }

        if &auth[..6].to_lowercase() != "digest" {
            return Err(DigestParseError::new(DigestParseErrorKind::MissingDigest));
        }
        let mut res = Self {
            www_authenticate: auth.to_owned(),
            nonce: StrPosition::default(),
            domain: None,
            realm: StrPosition::default(),
            opaque: StrPosition::default(),
            stale: false,
            nonce_count: 0,
            algorithm: DigestAlgorithm::MD5,
            session: false,
            userhash: false,
            qop: QualityOfProtection::None,
            qop_data: None,
        };

        let matcher = Regex::new(r#"(\S+)\s*=\s*(?:"([^"]+)"|(\S+))\s*(?:,\s*|$)"#).unwrap();
        for cap in matcher.captures_iter(auth) {
            let key = &cap[1].to_lowercase();
            let value = if let Some(v) = cap.get(2) {
                v
            } else if let Some(v) = cap.get(3) {
                v
            } else {
                // This isn't valid and should never happen
                continue;
            };
            if key == "nonce" {
                res.nonce = StrPosition {
                    start: value.start(),
                    end: value.end(),
                };
            } else if key == "realm" {
                res.realm = StrPosition {
                    start: value.start(),
                    end: value.end(),
                };
            } else if key == "domain" {
            	// @todo solve splitting
                // res.domain = Some(value.as_str().split(' ').collect());
            } else if key == "opaque" {
                res.opaque = StrPosition {
                    start: value.start(),
                    end: value.end(),
                };
            } else if key == "stale" && value.as_str().to_lowercase() == "true" {
                res.stale = true;
            } else if key == "algorithm" {
                let alg_str = value.as_str().to_lowercase();
                if alg_str == "md5-sess" {
                    res.session = true;
                } else if alg_str == "sha-256" {
                    res.algorithm = DigestAlgorithm::SHA256;
                } else if alg_str == "sha-256-sess" {
                    res.algorithm = DigestAlgorithm::SHA256;
                    res.session = true;
                }
            } else if key == "qop" {
                let qop_str = value.as_str().to_lowercase();
                if qop_str.contains(QualityOfProtection::AuthInt.to_str()) {
                    res.qop = QualityOfProtection::AuthInt;
                } else {
                    res.qop = QualityOfProtection::Auth;
                }
            } else if key == "userhash" && value.as_str().to_lowercase() == "true" {
                res.userhash = true;
            }
        }

        match (res.nonce.is_valid(), res.realm.is_valid()) {
            (true, true) => Ok(res),
            (true, false) => Err(DigestParseError::new(DigestParseErrorKind::MissingRealm)),
            (false, true) => Err(DigestParseError::new(DigestParseErrorKind::MissingNonce)),
            (false, false) => Err(DigestParseError::new(DigestParseErrorKind::MissingNonce)),
        }
    }
}

impl DigestScheme {
    pub fn www_authenticate_string(headers: &HeaderMap) -> Option<String> {
        if let Ok(a) = headers.get(WWW_AUTHENTICATE)?.to_str() {
            if &a[..7].to_lowercase() == "digest " {
                return Some(a.to_string());
            }
        }
        None
    }

    pub fn generate_auth_string(
        &mut self,
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
        cnonce: Option<&str>,
    ) -> String {
        self.qop_data = if self.qop != QualityOfProtection::None {
            let cnonce = match cnonce {
                Some(c) => c.to_owned(),
                None => Self::cnonce(),
            };
            self.nonce_count += 1;
            let count_str = format!("{:08.x}", self.nonce_count);
            let qop = if self.qop == QualityOfProtection::AuthInt && body.is_none() {
                QualityOfProtection::Auth
            } else {
                self.qop
            };
            Some(QualityOfProtectionData {
                cnonce,
                count_str,
                qop,
            })
        } else {
            None
        };
        let response = match self.algorithm {
            DigestAlgorithm::MD5 => {
                self.generate_response_string::<Md5>(username, password, method, uri, body)
            }
            DigestAlgorithm::SHA256 => {
                self.generate_response_string::<Sha256>(username, password, method, uri, body)
            }
        };
        let mut auth_str_len = 90
            + username.len()
            + self.realm().len()
            + self.nonce().len()
            + uri.len()
            + response.len();
        if self.qop != QualityOfProtection::None {
            let qop_data = self.qop_data.as_ref().unwrap();
            auth_str_len +=
                6 + qop_data.qop.to_str().len() + qop_data.count_str.len() + qop_data.cnonce.len();
        }
        if let Some(o) = self.opaque() {
            auth_str_len += 11 + o.len();
        }
        let mut auth = String::with_capacity(auth_str_len);
        auth.push_str("Digest username=\"");
        auth.push_str(username);
        auth.push_str("\", realm=\"");
        auth.push_str(self.realm());
        auth.push_str("\", nonce=\"");
        auth.push_str(self.nonce());
        auth.push_str("\", uri=\"");
        auth.push_str(uri);
        if self.qop != QualityOfProtection::None {
            let qop_data = self.qop_data.as_ref().unwrap();
            auth.push_str("\", qop=");
            auth.push_str(qop_data.qop.to_str());
            auth.push_str(", algorithm=");
            auth.push_str(self.algorithm.to_str());
            auth.push_str(", nc=");
            auth.push_str(&qop_data.count_str);
            auth.push_str(", cnonce=\"");
            auth.push_str(&qop_data.cnonce);
        }
        auth.push_str("\", response=\"");
        auth.push_str(&response);
        if let Some(o) = self.opaque() {
            auth.push_str("\", opaque=\"");
            auth.push_str(o);
        }
        auth.push('"');
        auth
    }

    fn realm(&self) -> &str {
        self.realm.to_str(&self.www_authenticate)
    }

    fn nonce(&self) -> &str {
        self.nonce.to_str(&self.www_authenticate)
    }

    fn opaque(&self) -> Option<&str> {
        if self.opaque.is_valid() {
            Some(self.opaque.to_str(&self.www_authenticate))
        } else {
            None
        }
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

    fn calculate_ha1<T: Digest>(&self, username: &str, password: &str) -> String {
        let mut hasher = T::new();
        hasher.input(username);
        hasher.input(":");
        hasher.input(self.realm());
        hasher.input(":");
        hasher.input(password);
        if self.session {
            let qop_data = self.qop_data.as_ref().unwrap();
            let digest = hasher.result_reset();
            hasher.input(digest);
            hasher.input(":");
            hasher.input(self.nonce());
            hasher.input(":");
            hasher.input(&qop_data.cnonce);
        }
        let digest = hasher.result();
        hex::encode(digest)
    }

    fn calculate_ha2<T: Digest>(&self, method: &str, uri: &str, body: Option<&str>) -> String {
        let mut hasher = T::new();
        hasher.input(method);
        hasher.input(":");
        hasher.input(uri);
        if self.qop != QualityOfProtection::None
            && self.qop_data.as_ref().unwrap().qop == QualityOfProtection::AuthInt
        {
            hasher.input(":");
            let mut body_hasher = T::new();
            body_hasher.input(body.unwrap());
            hasher.input(hex::encode(body_hasher.result()));
        }
        let digest = hasher.result();
        hex::encode(digest)
    }

    fn calculate_response<T: Digest>(&self, ha1: &str, ha2: &str) -> String {
        let mut hasher = T::new();
        hasher.input(ha1);
        hasher.input(":");
        println!("{}:{}:{}", ha1, self.nonce(), ha2);
        hasher.input(self.nonce());
        hasher.input(":");
        if self.qop != QualityOfProtection::None {
            let qop_data = self.qop_data.as_ref().unwrap();
            println!("Using QOP: {}", qop_data.qop.to_str());
            hasher.input(&qop_data.count_str);
            hasher.input(":");
            hasher.input(&qop_data.cnonce);
            hasher.input(":");
            hasher.input(qop_data.qop.to_str());
            hasher.input(":");
        }
        hasher.input(ha2);
        let digest = hasher.result();
        hex::encode(digest)
    }

    fn generate_response_string<T: Digest>(
        &self,
        username: &str,
        password: &str,
        method: &str,
        uri: &str,
        body: Option<&str>,
    ) -> String {
        let ha1 = self.calculate_ha1::<T>(username, password);

        let ha2 = self.calculate_ha2::<T>(method, uri, body);

        self.calculate_response::<T>(&ha1, &ha2)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc2069() {

        let rfc2069_test = r#"Digest realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let mut d = rfc2069_test.parse::<crate::digest_authenticator::DigestScheme>().unwrap();
        let auth_str = d.generate_auth_string("Mufasa", "CircleOfLife", "GET", "/dir/index.html", None, None);
        assert_eq!(auth_str, r#"Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", response="1949323746fe6a43ef61f9606e7febea", opaque="5ccc069c403ebaf9f0171e9517f40e41""#);
    }

    #[test]
    fn rfc2617() {
        let rfc2617_test = r#"Digest realm="testrealm@host.com", qop="auth", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let mut d = rfc2617_test.parse::<crate::digest_authenticator::DigestScheme>().unwrap();
        let auth_str = d.generate_auth_string("Mufasa", "Circle Of Life", "GET", "/dir/index.html", None, Some("0a4f113b"));
        assert_eq!(auth_str, r#"Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", qop=auth, algorithm=MD5, nc=00000001, cnonce="0a4f113b", response="6629fae49393a05397450978507c4ef1", opaque="5ccc069c403ebaf9f0171e9517f40e41""#);
    }

    #[test]
    fn rfc7617() {
        let rfc7617_test = r#"Digest
        realm="http-auth@example.org",
        qop="auth, auth-int",
        algorithm=SHA-256,
        nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v",
        opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#;

        let mut d = rfc7617_test.parse::<crate::digest_authenticator::DigestScheme>().unwrap();
        let auth_str = d.generate_auth_string("Mufasa", "Circle of Life", "GET", "/dir/index.html", None, Some("f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ"));

        assert_eq!(auth_str, r#"Digest username="Mufasa", realm="http-auth@example.org", nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", uri="/dir/index.html", qop=auth, algorithm=SHA-256, nc=00000001, cnonce="f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ", response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS""#);
    }
}

