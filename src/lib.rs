mod digest_authenticator;
pub use digest_authenticator::DigestScheme;

use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION};
use reqwest::IntoUrl;
use std::convert::TryFrom;
use std::future::Future;
use url::Position;

#[derive(Default, Clone)]
pub struct AuthenticatingClient {
    username: Option<String>,
    password: Option<String>,

    client: reqwest::Client,
}

pub struct AuthenticatingRequestBuilder {
    client: AuthenticatingClient,
    request: reqwest::RequestBuilder,
}

impl AuthenticatingClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_username(&mut self, user: &str) {
        self.username = Some(user.to_owned());
    }

    pub fn set_password(&mut self, pass: &str) {
        self.password = Some(pass.to_owned());
    }

    pub fn get<U: IntoUrl>(mut self, url: U) -> AuthenticatingRequestBuilder {
        let mut sanitised_url = url.into_url().unwrap();
        if !sanitised_url.username().is_empty() || sanitised_url.password().is_some() {
            self.set_username(sanitised_url.username());
            self.password = sanitised_url.password().map(|pass| pass.to_owned());
            sanitised_url.set_username("");
            sanitised_url.set_password(None);
        }
        AuthenticatingRequestBuilder::new(self.clone(), self.client.get(sanitised_url))
    }
}

impl AuthenticatingRequestBuilder {
    fn new(client: AuthenticatingClient, request: reqwest::RequestBuilder) -> Self {
        Self { client, request }
    }
    /// Add a `Header` to this Request.
    pub fn header<K, V>(self, key: K, value: V) -> Self
    where
        HeaderName: TryFrom<K>,
        <HeaderName as TryFrom<K>>::Error: Into<http::Error>,
        HeaderValue: TryFrom<V>,
        <HeaderValue as TryFrom<V>>::Error: Into<http::Error>,
    {
        Self {
            request: self.request.header(key, value),
            client: self.client,
        }
    }

    pub fn send(self) -> impl Future<Output = Result<reqwest::Response, reqwest::Error>> {
        async {
            match self.request.build() {
                Ok(req) => match self.client.client.execute(req).await {
                    Ok(response) => {
                        if let Some(a) = DigestScheme::www_authenticate_string(response.headers()) {
                            let url = response.url().to_owned();
                            let body = response.text().await.ok();
                            let mut auth_str = "".to_owned();

                            if let Ok(mut auth) = a.parse::<DigestScheme>() {
                                auth_str = auth.generate_auth_string(
                                    self.client.username.as_ref().unwrap(),
                                    self.client.password.as_ref().unwrap(),
                                    "GET",
                                    &url[Position::BeforePath..],
                                    body.as_ref().map(|s| &**s),
                                    None
                                );
                            }
                            return self
                                .client
                                .client
                                .get(url)
                                .header(AUTHORIZATION, auth_str)
                                .send()
                                .await;
                        }
                        Ok(response)
                    }
                    Err(err) => Err(err),
                },

                Err(err) => Err(err),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc2069() {

        let rfc2069_test = r#"Digest realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41""#;
        let mut d = rfc2069_test.parse::<crate::digest_authenticator::DigestScheme>().unwrap();
        let auth_str = d.generate_auth_string("Mufasa", "CircleOfLife", "GET", "/dir/index.html", None, None);
        assert_eq!(auth_str, r#"Digest username="Mufasa", realm="testrealm@host.com", nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", uri="/dir/index.html", response="e966c932a9242554e42c8ee200cec7f6", opaque="5ccc069c403ebaf9f0171e9517f40e41""#);
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
