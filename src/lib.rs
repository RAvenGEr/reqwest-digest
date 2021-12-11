use digest_access::DigestAccess;
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
                    if self.client.username.is_some() && self.client.password.is_some() {
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
        let unauthorised_client = crate::AuthenticatingClient::new();

        if let Ok(stream) = unauthorised_client.get(&uri).send().await {
            assert_eq!(stream.status(), http::StatusCode::UNAUTHORIZED);
        }

        let mut client = crate::AuthenticatingClient::new();
        client.set_username(user);
        client.set_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), http::StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_auth_sha256() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth", user, password, Some("sha256"));

        let mut client = crate::AuthenticatingClient::new();
        client.set_username(user);
        client.set_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), http::StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_authint_sha256() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth-int", user, password, Some("sha256"));

        let mut client = crate::AuthenticatingClient::new();
        client.set_username(user);
        client.set_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), http::StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn httpbin_auth_md5() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = httpbin_uri("auth", user, password, Some("md5"));

        let mut client = crate::AuthenticatingClient::new();
        client.set_username(user);
        client.set_password(password);
        if let Ok(stream) = client.get(&uri).send().await {
            assert_eq!(stream.status(), http::StatusCode::OK);
        }
    }
}
