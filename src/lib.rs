use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION, WWW_AUTHENTICATE};
use reqwest::IntoUrl;
use std::convert::TryFrom;
use url::Position;

#[derive(Default, Clone)]
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
    pub fn new(basic_fallback: bool) -> Self {
        Self {
            username: None,
            password: None,
            basic_fallback,
            client: reqwest::Client::default(),
        }
    }

    pub fn set_username<S: Into<String>>(&mut self, user: S) {
        self.username = Some(user.into());
    }

    pub fn set_password<S: Into<String>>(&mut self, pass: S) {
        self.password = Some(pass.into());
    }

    pub fn clear_credentials(&mut self) {
        self.username = None;
        self.password = None;
    }

    pub fn set_basic_fallback(&mut self, enable: bool) {
        self.basic_fallback = enable;
    }

    pub fn get<U: IntoUrl>(mut self, url: U) -> AuthenticatingRequestBuilder {
        // Don't leak username and password via basic auth, if we can avoid it
        let mut sanitised_url = url.into_url().unwrap();
        if !sanitised_url.username().is_empty() || sanitised_url.password().is_some() {
            if self.username.is_none() {
                self.set_username(sanitised_url.username());
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

        let mut client = AuthenticatingClient::default();
        client.set_username(user);
        client.set_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_auth_sha256() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth", user, password, Some("sha256"));

        let mut client = AuthenticatingClient::default();
        client.set_username(user);
        client.set_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_authint_sha256() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth-int", user, password, Some("sha256"));

        let mut client = AuthenticatingClient::default();
        client.set_username(user);
        client.set_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_auth_md5() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth", user, password, Some("md5"));

        let mut client = AuthenticatingClient::default();
        client.set_username(user);
        client.set_password(password);
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
        let mut client = AuthenticatingClient::new(false);
        client.set_username(user);
        client.set_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_ne!(stream.status(), StatusCode::OK);
        }

        // Basic fallback not enabled, url does contain username and password
        let client = crate::AuthenticatingClient::default();
        if let Ok(stream) = client.get(&uri_with_auth).send().await {
            // Still not OK response
            assert_ne!(stream.status(), StatusCode::OK);
        }

        // Enable basic fallback, use auth in uri
        let client = crate::AuthenticatingClient::new(true);
        if let Ok(stream) = client.get(&uri_with_auth).send().await {
            // OK response
            assert_eq!(stream.status(), StatusCode::OK);
        }

        // Enable basic fallback, set auth in client
        let mut client = crate::AuthenticatingClient::default();
        client.set_username(user);
        client.set_password(password);
        client.set_basic_fallback(true);
        if let Ok(stream) = client.get(&uri).send().await {
            // OK response
            assert_eq!(stream.status(), StatusCode::OK);
        }
    }
}
