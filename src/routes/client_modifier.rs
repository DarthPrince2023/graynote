use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde::Deserialize;

use crate::routes::Error;

///
/// The type of the HTTP request we want to send
/// 
#[derive(Debug, Clone)]
pub enum RequestType {
    Post,
    Head,
    Get,
    Put,
    Patch,
    Delete
}

///
/// Parameters for basic HTTP authentication
/// 
#[derive(Debug, Clone, Deserialize)]
pub struct BasicAuth {
    pub username: String,
    pub password: Option<String>
}

impl BasicAuth {
    pub fn new(username: String, password: Option<String>) -> Self {
        Self {
            username, password
        }
    }

    pub fn set_username(&mut self, username: String) -> &mut Self {
        self.username = username;

        self
    }

    pub fn set_password(&mut self, password: Option<String>) -> &mut Self {
        self.password = password;

        self
    }
}

///
/// Extension for `'reqwest::Client'`
/// The purpose of this extension is so we can modify a client in-line,
/// rather than having to work with complex logic, wrap it in a client extension
/// 
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    pub client: Client,
    pub request_type: RequestType,
    pub url: String,
    pub content_type: Option<String>,
    pub body: Option<Vec<u8>>,
    pub basic_auth: Option<BasicAuth>,
    pub bearer_auth: Option<String>,
    pub timeout: u64,
}

///
/// Implement our `'ClientBuilder'` object, an extension for building Clients
/// 
impl ClientBuilder {
    pub fn new(request_type: RequestType, url: String, content_type: Option<String>, body: Option<Vec<u8>>, basic_auth: Option<BasicAuth>, bearer_auth: Option<String>) -> Self {
        let client = Client::new();

        Self {
            client,
            request_type,
            url,
            content_type,
            body,
            basic_auth,
            bearer_auth,
            timeout: 300u64
        }
    }
    
    pub fn set_request_type(&mut self, request_type: RequestType) -> &mut Self {
        self.request_type = request_type;

        self
    }

    pub fn set_url(&mut self, url: String) -> &mut Self {
        self.url = url;

        self
    }

    pub fn set_content_type(&mut self, content_type: Option<String>) -> &mut Self {
        self.content_type = content_type;

        self
    }

    pub fn set_body(&mut self, body: Option<Vec<u8>>) -> &mut Self {
        self.body = body;

        self
    }

    pub fn set_basic_auth(&mut self, basic_auth: Option<BasicAuth>) -> &mut Self {
        self.basic_auth = basic_auth;

        self
    }

    pub fn set_bearer_auth(&mut self, bearer_auth: Option<String>) -> &mut Self {
        self.bearer_auth = bearer_auth;

        self
    }

    pub fn set_timeout(&mut self, seconds: u64) -> &mut Self {
        self.timeout = seconds;

        self
    }

    pub fn get_client_with_auth(&mut self) -> RequestBuilder {
        let request_client = match self.request_type {
            RequestType::Delete => self.client.delete(&self.url),
            RequestType::Get => self.client.get(&self.url),
            RequestType::Post => self.client.post(&self.url),
            RequestType::Head => self.client.head(&self.url),
            RequestType::Patch => self.client.patch(&self.url),
            RequestType::Put => self.client.put(&self.url)
        };

        if let Some(auth) = &self.bearer_auth {
            request_client.bearer_auth(auth)
        } else if let Some(auth) = &self.basic_auth {
            request_client.basic_auth(auth.username.to_string(), auth.password.clone())
        } else {
            request_client
        }
    }

    ///
    /// Send the request, get the response bytes or `'Error'` on fail
    /// 
    pub async fn send_request(&mut self) -> Result<Vec<u8>, Error> {
        let client = self.get_client_with_auth();
        let content_type = self.content_type.clone().unwrap_or("application/json".into());
        let default_body = self.body.clone().unwrap_or_default();
        let response_bytes = client
            .header("Content-Type", content_type)
            .body(default_body)
            .timeout(Duration::from_secs(self.timeout))
            .send()
            .await?
            .bytes()
            .await?
            .to_vec();

        Ok(response_bytes)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    #[test]
    pub fn can_send_request() {
        let mut client = ClientBuilder::new(RequestType::Post, "https://google.com".into(), Some("application/json".into()), None, None, None);

        assert!(matches!(client.request_type, RequestType::Post));
        client.set_request_type(RequestType::Delete);
        assert!(matches!(client.request_type, RequestType::Delete));
    }
}
