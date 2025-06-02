use std::{collections::HashMap, str};

static HTTP_METHODS: [&'static str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

/// Represents a parsed HTTP request with basic fields
#[derive(Debug)]
pub struct HTTPRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HTTPRequest {
    pub fn is_request(payload: &[u8]) -> bool {
        if let Ok(text) = str::from_utf8(payload) {
            return HTTP_METHODS.iter().any(|m| text.starts_with(m));
        }
        false
    }

    pub fn parse(payload: &[u8]) -> Option<Self> {
        let text = str::from_utf8(payload).ok()?;
        let mut lines = text.split("\r\n");

        // The first line typically contains METHOD, PATH, and HTTP VERSION
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_string();
        let path = parts.next()?.to_string();
        let version = parts.next()?.to_string();

        // The remaining lines are headers until an empty line (body follows)
        let mut headers = HashMap::new();
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(": ") {
                headers.insert(key.to_string(), value.to_string());
            }
        }

        let remaining_bytes = lines
            .collect::<Vec<&str>>()
            .join("\r\n")
            .as_bytes()
            .to_vec();

        Some(Self {
            method,
            path,
            version,
            headers,
            body: remaining_bytes,
        })
    }
}

/// Represents a parsed HTTP response with basic fields
#[derive(Debug)]
pub struct HTTPResponse {
    pub version: String,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl HTTPResponse {
    pub fn is_response(payload: &[u8]) -> bool {
        if let Ok(text) = str::from_utf8(payload) {
            return text.starts_with("HTTP/");
        }
        false
    }

    pub fn parse(payload: &[u8]) -> Option<Self> {
        let text = str::from_utf8(payload).ok()?;
        let mut lines = text.split("\r\n");

        // The first line typically contains HTTP version, status code, and reason phrase
        let status_line = lines.next()?;
        let mut parts = status_line.split_whitespace();
        let version = parts.next()?.to_string();
        let status_code = parts.next()?.parse().ok()?;
        let reason_phrase = parts.collect::<Vec<&str>>().join(" ");

        // The remaining lines are headers until an empty line (body follows)
        let mut headers = HashMap::new();
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(": ") {
                headers.insert(key.to_string(), value.to_string());
            }
        }

        let remaining_bytes = lines
            .collect::<Vec<&str>>()
            .join("\r\n")
            .as_bytes()
            .to_vec();

        Some(Self {
            version,
            status_code,
            reason_phrase,
            headers,
            body: remaining_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_request() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(HTTPRequest::is_request(req));
        let not_req = b"FAKE /something \r\n\r\n";
        assert!(!HTTPRequest::is_request(not_req));
    }

    #[test]
    fn test_is_http_response() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>...</html>";
        assert!(HTTPResponse::is_response(resp));
        let not_resp = b"Something else\r\n\r\n";
        assert!(!HTTPResponse::is_response(not_resp));
    }

    #[test]
    fn test_parse_request() {
        let req = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n\r\nHello World";
        let parsed = HTTPRequest::parse(req).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/submit");
        assert_eq!(parsed.version, "HTTP/1.1");
        assert_eq!(parsed.headers.get("Host"), Some(&"example.com".to_string()));
        assert_eq!(parsed.body, b"Hello World");
    }

    #[test]
    fn test_parse_response() {
        let resp =
            b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n<html>Not Found</html>";
        let parsed = HTTPResponse::parse(resp).unwrap();
        assert_eq!(parsed.version, "HTTP/1.1");
        assert_eq!(parsed.status_code, 404);
        assert_eq!(parsed.reason_phrase, "Not Found");
        assert_eq!(
            parsed.headers.get("Content-Type"),
            Some(&"text/html".to_string())
        );
        assert_eq!(parsed.body, b"<html>Not Found</html>");
    }
}
