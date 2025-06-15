use std::collections::HashMap;
use std::str;

use thiserror::Error;

static HTTP_METHODS: [&'static str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

#[derive(Error, Debug, PartialEq)]
pub enum ParseError {
    #[error("invalid UTF-8")]
    InvalidUtf8,

    #[error("missing start line")]
    MissingStartLine,

    #[error("not enough parts on start line")]
    NotEnoughStartLineParts,

    #[error("missing headers terminator (\\r\\n\\r\\n)")]
    MissingHeaderTerminator,

    #[error("invalid header line: {0}")]
    InvalidHeaderLine(String),

    #[error("invalid status code: {0}")]
    InvalidStatusCode(String),
}

/// A thin trait for parsing the start-line of both requests and responses.
pub trait HttpMessage<'a>: Sized {
    /// True if payload *looks* like this message type.
    fn is_type(text: &str) -> bool;

    /// Parse the version + maybe method or status, leaving the rest behind.
    fn parse_head(parts: &[&'a str]) -> Result<Self, ParseError>;

    /// The all-in-one parse entry point.
    fn parse(payload: &'a [u8]) -> Result<Parsed<'a, Self>, ParseError> {
        let text = str::from_utf8(payload).map_err(|_| ParseError::InvalidUtf8)?;
        let (head, rest) = split_once(text, "\r\n").ok_or(ParseError::MissingStartLine)?;
        let parts: Vec<&str> = head.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(ParseError::NotEnoughStartLineParts);
        }
        let message = Self::parse_head(&parts)?;
        let (headers, body) = parse_headers_and_body(rest)?;
        Ok(Parsed {
            message,
            headers,
            body,
        })
    }
}

/// The final result of parsing, with owned header map but borrowed keys/values.
#[derive(Debug)]
pub struct Parsed<'a, T> {
    pub message: T,
    pub headers: HashMap<&'a str, &'a str>,
    pub body: &'a [u8],
}

impl<'a, T> Parsed<'a, T> {
    /// Lookup a header value by case-sensitive header name.
    pub fn header_value(&self, key: &str) -> Option<&'a str> {
        self.headers.get(key).copied()
    }
}

fn split_once<'a>(s: &'a str, pat: &str) -> Option<(&'a str, &'a str)> {
    s.find(pat).map(|i| (&s[..i], &s[i + pat.len()..]))
}

/// Parses all headers, returns a borrowed map of &str to &str + body slice.
fn parse_headers_and_body<'a>(
    rest: &'a str,
) -> Result<(HashMap<&'a str, &'a str>, &'a [u8]), ParseError> {
    let (head, tail) = split_once(rest, "\r\n\r\n").ok_or(ParseError::MissingHeaderTerminator)?;
    let mut map = HashMap::new();

    for line in head.split("\r\n") {
        let (k, v) = line
            .split_once(": ")
            .ok_or(ParseError::InvalidHeaderLine(line.to_string()))?;
        map.insert(k, v);
    }

    let raw = rest.as_bytes();
    // tail is the part after "\r\n\r\n"
    let body_start = rest.len() - tail.len();
    Ok((map, &raw[body_start..]))
}

/// Represents a parsed HTTP request (lifetime `'a` borrows from the original payload)
#[derive(Debug, PartialEq)]
pub struct HTTPRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub version: &'a str,
}

impl<'a> HTTPRequest<'a> {
    /// Check if this payload is a request: valid UTF-8 and starts with known method
    pub fn is_request(payload: &[u8]) -> bool {
        if let Ok(text) = str::from_utf8(payload) {
            Self::is_type(text)
        } else {
            false
        }
    }
}

impl<'a> HttpMessage<'a> for HTTPRequest<'a> {
    fn is_type(text: &str) -> bool {
        HTTP_METHODS.iter().any(|&m| text.starts_with(m))
    }

    fn parse_head(parts: &[&'a str]) -> Result<Self, ParseError> {
        let method = parts[0];
        if !HTTP_METHODS.contains(&method) {
            return Err(ParseError::MissingStartLine);
        }
        let path = *parts.get(1).ok_or(ParseError::NotEnoughStartLineParts)?;
        let version = *parts.get(2).ok_or(ParseError::NotEnoughStartLineParts)?;
        Ok(HTTPRequest {
            method,
            path,
            version,
        })
    }
}

/// Represents a parsed HTTP response (lifetime `'a` borrows from the original payload)
#[derive(Debug)]
pub struct HTTPResponse<'a> {
    pub version: &'a str,
    pub status_code: u16,
    pub reason_phrase: String,
}

impl<'a> HTTPResponse<'a> {
    /// Check if this payload is a response: valid UTF-8 and starts with "HTTP/"
    pub fn is_response(payload: &[u8]) -> bool {
        if let Ok(text) = str::from_utf8(payload) {
            Self::is_type(text)
        } else {
            false
        }
    }
}

impl<'a> HttpMessage<'a> for HTTPResponse<'a> {
    fn is_type(text: &str) -> bool {
        text.starts_with("HTTP/")
    }

    fn parse_head(parts: &[&'a str]) -> Result<Self, ParseError> {
        let version = parts[0];
        if !version.starts_with("HTTP/") {
            return Err(ParseError::MissingStartLine);
        }
        if parts.len() < 3 {
            return Err(ParseError::NotEnoughStartLineParts);
        }
        let status_str = parts[1];
        let status_code = status_str
            .parse::<u16>()
            .map_err(|_| ParseError::InvalidStatusCode(status_str.to_string()))?;
        let reason_phrase = parts[2..].join(" ");
        Ok(HTTPResponse {
            version,
            status_code,
            reason_phrase,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_http_request_positive() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(HTTPRequest::is_request(req));
    }

    #[test]
    fn test_is_http_request_negative() {
        // Doesn’t start with any known method
        let not_req = b"FAKE /something HTTP/1.1\r\n\r\n";
        assert!(!HTTPRequest::is_request(not_req));

        // Invalid UTF-8 should also return false
        let invalid_utf8 = b"\xFF\xFF\xFF";
        assert!(!HTTPRequest::is_request(invalid_utf8));
    }

    #[test]
    fn test_is_http_response_positive() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>...</html>";
        assert!(HTTPResponse::is_response(resp));
    }

    #[test]
    fn test_is_http_response_negative() {
        let not_resp = b"Something else\r\n\r\n";
        assert!(!HTTPResponse::is_response(not_resp));

        let invalid_utf8 = b"\xFF\xFE";
        assert!(!HTTPResponse::is_response(invalid_utf8));
    }

    #[test]
    fn test_parse_request_minimal_no_body() {
        let raw = b"GET / HTTP/1.0\r\nHost: example.org\r\n\r\n";
        let parsed = HTTPRequest::parse(raw).unwrap();

        assert_eq!(parsed.message.method, "GET");
        assert_eq!(parsed.message.path, "/");
        assert_eq!(parsed.message.version, "HTTP/1.0");

        // Only one header
        assert_eq!(parsed.headers.len(), 1);
        assert_eq!(parsed.header_value("Host"), Some("example.org"));
        assert_eq!(parsed.header_value("Non-Existent"), None);

        // No body after the blank line
        assert_eq!(parsed.body.len(), 0);
    }

    #[test]
    fn test_parse_request_with_body_and_multiple_headers() {
        let raw = b"POST /submit HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    Content-Type: text/plain\r\n\
                    Content-Length: 11\r\n\
                    \r\n\
                    Hello World";
        let parsed = HTTPRequest::parse(raw).unwrap();

        assert_eq!(parsed.message.method, "POST");
        assert_eq!(parsed.message.path, "/submit");
        assert_eq!(parsed.message.version, "HTTP/1.1");

        assert_eq!(parsed.headers.len(), 3);
        assert_eq!(parsed.header_value("Host"), Some("example.com"));
        assert_eq!(parsed.header_value("Content-Type"), Some("text/plain"));
        assert_eq!(parsed.header_value("Content-Length"), Some("11"));

        assert_eq!(parsed.body, b"Hello World");
    }

    #[test]
    fn test_parse_request_invalid_utf8() {
        // Completely invalid UTF-8
        let raw = b"\xFF\xFF\xFF\r\nHost: foo\r\n\r\n";
        let err = HTTPRequest::parse(raw).unwrap_err();
        assert_eq!(err, ParseError::InvalidUtf8);
    }

    #[test]
    fn test_parse_request_missing_start_line() {
        // No "\r\n" at all
        let raw = b"";
        let err = HTTPRequest::parse(raw).unwrap_err();
        assert_eq!(err, ParseError::MissingStartLine);

        // Or only headers, no request line
        let raw = b"Host: example.com\r\n\r\n";
        let err2 = HTTPRequest::parse(raw).unwrap_err();
        assert_eq!(err2, ParseError::MissingStartLine);
    }

    #[test]
    fn test_parse_request_not_enough_start_line_parts() {
        // Missing path and/or version
        let raw1 = b"GET\r\nHost: foo\r\n\r\n"; // only method
        let err1 = HTTPRequest::parse(raw1).unwrap_err();
        assert_eq!(err1, ParseError::NotEnoughStartLineParts);

        let raw2 = b"GET / \r\nHost: foo\r\n\r\n"; // no version
        let err2 = HTTPRequest::parse(raw2).unwrap_err();
        assert_eq!(err2, ParseError::NotEnoughStartLineParts);
    }

    #[test]
    fn test_parse_request_missing_header_terminator() {
        // No blank line after headers
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: text/plain\r\n";
        let err = HTTPRequest::parse(raw).unwrap_err();
        assert_eq!(err, ParseError::MissingHeaderTerminator);
    }

    #[test]
    fn test_parse_request_invalid_header_line() {
        // Header missing “: ”
        let raw = b"GET / HTTP/1.1\r\nHost example.com\r\n\r\n";
        let err = HTTPRequest::parse(raw).unwrap_err();
        match err {
            ParseError::InvalidHeaderLine(line) => assert_eq!(line, "Host example.com"),
            _ => panic!("expected InvalidHeaderLine"),
        }
    }

    #[test]
    fn test_parse_response_minimal_no_body() {
        let raw = b"HTTP/1.0 204 No Content\r\nServer: RustTest\r\n\r\n";
        let parsed = HTTPResponse::parse(raw).unwrap();

        assert_eq!(parsed.message.version, "HTTP/1.0");
        assert_eq!(parsed.message.status_code, 204);
        assert_eq!(parsed.message.reason_phrase, "No Content");

        assert_eq!(parsed.headers.len(), 1);
        assert_eq!(parsed.header_value("Server"), Some("RustTest"));
        assert_eq!(parsed.header_value("Date"), None);

        assert_eq!(parsed.body.len(), 0);
    }

    #[test]
    fn test_parse_response_with_body_and_multiple_headers() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\
                    Content-Type: text/html\r\n\
                    Content-Length: 19\r\n\
                    \r\n\
                    <html>NotFound</html>";
        let parsed = HTTPResponse::parse(raw).unwrap();

        assert_eq!(parsed.message.version, "HTTP/1.1");
        assert_eq!(parsed.message.status_code, 404);
        assert_eq!(parsed.message.reason_phrase, "Not Found");

        assert_eq!(parsed.headers.len(), 2);
        assert_eq!(parsed.header_value("Content-Type"), Some("text/html"));
        assert_eq!(parsed.header_value("Content-Length"), Some("19"));

        assert_eq!(parsed.body, b"<html>NotFound</html>");
    }

    #[test]
    fn test_parse_response_invalid_utf8() {
        let raw = b"\xFF\xFF\r\n\r\n";
        let err = HTTPResponse::parse(raw).unwrap_err();
        assert_eq!(err, ParseError::InvalidUtf8);
    }

    #[test]
    fn test_parse_response_missing_start_line() {
        // No "\r\n" at all
        let raw = b"";
        let err = HTTPResponse::parse(raw).unwrap_err();
        assert_eq!(err, ParseError::MissingStartLine);

        // Or headers only
        let raw = b"Content-Type: text/plain\r\n\r\n";
        let err2 = HTTPResponse::parse(raw).unwrap_err();
        assert_eq!(err2, ParseError::MissingStartLine);
    }

    #[test]
    fn test_parse_response_not_enough_start_line_parts() {
        // Missing status code and/or reason phrase
        let raw1 = b"HTTP/1.1\r\nServer: foo\r\n\r\n"; // no status code
        let err1 = HTTPResponse::parse(raw1).unwrap_err();
        assert_eq!(err1, ParseError::NotEnoughStartLineParts);

        let raw2 = b"HTTP/1.1 ABC\r\nServer: foo\r\n\r\n"; // status code present, but missing reason phrase
        let err2 = HTTPResponse::parse(raw2).unwrap_err();
        assert_eq!(err2, ParseError::NotEnoughStartLineParts);
    }

    #[test]
    fn test_parse_response_invalid_status_code() {
        // Status code "ABC" is not a valid u16
        let raw = b"HTTP/1.1 ABC NotOK\r\nContent-Type: text/plain\r\n\r\nHi";
        let err = HTTPResponse::parse(raw).unwrap_err();
        match err {
            ParseError::InvalidStatusCode(parse_err) => {
                // Underlying parse error should mention “ABC”
                let msg = parse_err.to_string();
                assert!(msg.contains("ABC"));
            }
            _ => panic!("expected InvalidStatusCode"),
        }
    }

    #[test]
    fn test_parse_response_missing_header_terminator() {
        // No blank line after headers
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n";
        let err = HTTPResponse::parse(raw).unwrap_err();
        assert_eq!(err, ParseError::MissingHeaderTerminator);
    }

    #[test]
    fn test_parse_response_invalid_header_line() {
        // Header missing “: ”
        let raw = b"HTTP/1.1 200 OK\r\nBadHeaderLine\r\n\r\nHello";
        let err = HTTPResponse::parse(raw).unwrap_err();
        match err {
            ParseError::InvalidHeaderLine(line) => assert_eq!(line, "BadHeaderLine"),
            _ => panic!("expected InvalidHeaderLine"),
        }
    }

    #[test]
    fn test_request_header_value_none_and_some() {
        let raw = b"GET /abc HTTP/1.1\r\nHeader1: Val1\r\n\r\n";
        let parsed = HTTPRequest::parse(raw).unwrap();
        assert_eq!(parsed.header_value("Header1"), Some("Val1"));
        assert_eq!(parsed.header_value("Missing"), None);
    }

    #[test]
    fn test_response_header_value_none_and_some() {
        let raw = b"HTTP/1.1 201 Created\r\nLocation: /new\r\n\r\n";
        let parsed = HTTPResponse::parse(raw).unwrap();
        assert_eq!(parsed.header_value("Location"), Some("/new"));
        assert_eq!(parsed.header_value("X-Does-Not-Exist"), None);
    }
}
