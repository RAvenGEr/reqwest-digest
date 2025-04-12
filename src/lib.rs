use reqwest::IntoUrl;
use reqwest::header::{AUTHORIZATION, HeaderName, HeaderValue, WWW_AUTHENTICATE};
use std::convert::TryFrom;
use std::time::Duration;
use url::Position;

#[derive(Clone, Default)]
pub struct AuthenticatingClient {
    username: Option<String>,
    password: Option<String>,
    basic_fallback: bool,
    client: reqwest::Client,
}

pub struct AuthenticatingRequestBuilder {
    client: AuthenticatingClient,
    request: reqwest::RequestBuilder,
}

impl AuthenticatingClient {
    pub fn with_username<S: Into<String>>(mut self, user: S) -> Self {
        self.username = Some(user.into());
        self
    }

    pub fn with_password<S: Into<String>>(mut self, pass: S) -> Self {
        self.password = Some(pass.into());
        self
    }

    pub fn with_basic_fallback(mut self) -> Self {
        self.basic_fallback = true;
        self
    }

    pub fn set_username<S: Into<String>>(&mut self, user: Option<S>) -> &mut Self {
        self.username = user.map(|user| user.into());
        self
    }

    pub fn set_password<S: Into<String>>(&mut self, pass: S) -> &mut Self {
        self.password = Some(pass.into());
        self
    }

    pub fn set_basic_fallback(mut self, fallback: bool) -> Self {
        self.basic_fallback = fallback;
        self
    }

    pub fn clear_credentials(&mut self) {
        self.username = None;
        self.password = None;
    }

    pub fn get<U: IntoUrl>(mut self, url: U) -> AuthenticatingRequestBuilder {
        // Don't leak username and password via basic auth, if we can avoid it
        let mut sanitised_url = url.into_url().unwrap();
        if !sanitised_url.username().is_empty() || sanitised_url.password().is_some() {
            if self.username.is_none() {
                self.username = Some(sanitised_url.username().to_string());
            }
            if self.password.is_none() {
                self.password = sanitised_url.password().map(|pass| pass.to_owned());
            }
            let _ = sanitised_url.set_username("");
            let _ = sanitised_url.set_password(None);
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

    /// Enables a request timeout
    pub fn timeout(self, timeout: Duration) -> Self {
        Self {
            request: self.request.timeout(timeout),
            client: self.client,
        }
    }

    pub async fn send(self) -> reqwest::Result<reqwest::Response> {
        match self.request.build() {
            Ok(req) => match self.client.client.execute(req).await {
                Ok(response) => {
                    if response.status().is_client_error()
                        && self.client.username.is_some()
                        && self.client.password.is_some()
                    {
                        if let Ok(mut auth) =
                            digest_access::DigestAccess::try_from(response.headers())
                        {
                            let url = response.url().to_owned();
                            let body = response.bytes().await;
                            let body_slice: Option<&[u8]> = match &body {
                                Ok(b) => Some(b),
                                Err(_) => None,
                            };

                            auth.set_username(self.client.username.as_ref().unwrap());
                            auth.set_password(self.client.password.as_ref().unwrap());
                            let a = auth
                                .generate_authorization(
                                    "GET",
                                    &url[Position::BeforePath..],
                                    body_slice,
                                    None,
                                )
                                .unwrap();
                            return self
                                .client
                                .client
                                .get(url)
                                .header(AUTHORIZATION, a)
                                .send()
                                .await;
                        } else if self.client.basic_fallback {
                            let auth_headers = response.headers().get_all(WWW_AUTHENTICATE);
                            for header in auth_headers {
                                if let Ok(h_str) = header.to_str() {
                                    if h_str.to_ascii_lowercase().contains("basic") {
                                        // looks like the server supports basic authentication, fallback to support provided by reqwest
                                        let mut url = response.url().to_owned();
                                        if url
                                            .set_username(self.client.username.as_ref().unwrap())
                                            .is_err()
                                        {
                                            continue;
                                        }
                                        if url
                                            .set_password(Some(
                                                self.client.password.as_ref().unwrap(),
                                            ))
                                            .is_err()
                                        {
                                            continue;
                                        }
                                        return self.client.client.get(url).send().await;
                                    }
                                }
                            }
                        }
                    }
                    Ok(response)
                }
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;

    use crate::*;

    fn httpbin_uri(auth: &str, user: &str, password: &str, algorithm: Option<&str>) -> String {
        let mut uri = format!(
            "http://httpbin.org/digest-auth/{}/{}/{}",
            auth, user, password
        );
        if let Some(algo) = algorithm {
            uri.push('/');
            uri.push_str(algo);
        }
        uri
    }

    #[tokio::test]
    async fn httpbin_auth() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth", user, password, None);
        let unauthorised_client = AuthenticatingClient::default();

        if let Ok(stream) = unauthorised_client.get(&uri).send().await {
            assert_eq!(stream.status(), StatusCode::UNAUTHORIZED);
        }

        let client = AuthenticatingClient::default()
            .with_username(user)
            .with_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_auth_sha256() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth", user, password, Some("sha256"));

        let client = AuthenticatingClient::default()
            .with_username(user)
            .with_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_authint_sha256() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth-int", user, password, Some("sha256"));

        let client = AuthenticatingClient::default()
            .with_username(user)
            .with_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_auth_md5() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth", user, password, Some("md5"));

        let client = AuthenticatingClient::default()
            .with_username(user)
            .with_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_auth_basic_fallback() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = format!("http://httpbin.org/basic-auth/{}/{}", user, password);
        let uri_with_auth = format!(
            "http://{u}:{p}@httpbin.org/basic-auth/{u}/{p}",
            u = user,
            p = password
        );

        // Basic fallback not enabled, url does not contain username or password
        let client = AuthenticatingClient::default()
            .with_username(user)
            .with_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_ne!(stream.status(), StatusCode::OK);
        }

        // Basic fallback not enabled, url does contain username and password
        let client = AuthenticatingClient::default();
        if let Ok(stream) = client.get(&uri_with_auth).send().await {
            // Still not OK response
            assert_ne!(stream.status(), StatusCode::OK);
        }

        // Enable basic fallback, use auth in uri
        let client = AuthenticatingClient::default().with_basic_fallback();
        if let Ok(stream) = client.get(&uri_with_auth).send().await {
            // OK response
            assert_eq!(stream.status(), StatusCode::OK);
        }

        // Enable basic fallback, set auth in client
        let client = AuthenticatingClient::default()
            .with_username(user)
            .with_password(password)
            .with_basic_fallback();
        if let Ok(stream) = client.get(&uri).send().await {
            // OK response
            assert_eq!(stream.status(), StatusCode::OK);
        }
    }
}
