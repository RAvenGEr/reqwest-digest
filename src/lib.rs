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
                        if let Some(a) =
                            digest_access::digest_authenticate_from_headers(response.headers())
                        {
                            if self.client.username.is_none() || self.client.password.is_none() {
                                return Ok(response);
                            }
                            let url = response.url().to_owned();
                            let body = response.text().await.ok();
                            let mut auth_str = "".to_owned();

                            if let Ok(mut auth) = a.parse::<DigestAccess>() {
                                auth_str = auth.generate_authentication(
                                    self.client.username.as_ref().unwrap(),
                                    self.client.password.as_ref().unwrap(),
                                    "GET",
                                    &url[Position::BeforePath..],
                                    body.as_ref().map(|s| &**s),
                                    None,
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
    #[tokio::test]
    async fn httpbin() {
        let user = "FredJones";
        let password = "P@55w0rd";
        let uri = format!(
            "http://httpbin.org/digest-auth/auth/{}/{}/sha256",
            user, password
        );
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
}
