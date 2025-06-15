use std::collections::HashMap;
use std::str;

static HTTP_METHODS: [&'static str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

#[derive(Debug, PartialEq)]
pub enum ParseError {
    InvalidUtf8,
    MissingStartLine,
    NotEnoughStartLineParts,
    MissingHeaderTerminator,
    InvalidHeaderLine(String),
    InvalidStatusCode(String),
}

/// Given the text _after_ the first line (i.e. everything from just past "\r\n"
/// through the end of the buffer), find the "\r\n\r\n" that ends the headers.
/// Return a (headers map, body slice).
fn parse_headers_and_body(full: &str) -> Result<(HashMap<String, String>, &[u8]), ParseError> {
    if let Some(idx) = full.find("\r\n\r\n") {
        let header_block = &full[..idx];
        let body_start = idx + 4; // skip past "\r\n\r\n"
        let mut headers = HashMap::new();

        for line in header_block.split("\r\n") {
            if let Some((key, val)) = line.split_once(": ") {
                headers.insert(key.to_string(), val.to_string());
            } else {
                return Err(ParseError::InvalidHeaderLine(line.to_string()));
            }
        }

        let raw_bytes = full.as_bytes();
        Ok((headers, &raw_bytes[body_start..]))
    } else {
        Err(ParseError::MissingHeaderTerminator)
    }
}

/// Represents a parsed HTTP request (lifetime `'a` borrows from the original payload)
#[derive(Debug)]
pub struct HTTPRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub version: &'a str,
    pub headers: HashMap<String, String>,
    pub body: &'a [u8],
}

impl<'a> HTTPRequest<'a> {
    pub fn is_request(payload: &[u8]) -> bool {
        if let Ok(text) = str::from_utf8(payload) {
            HTTP_METHODS.iter().any(|&m| text.starts_with(m))
        } else {
            false
        }
    }

    pub fn parse(payload: &'a [u8]) -> Result<Self, ParseError> {
        let text = str::from_utf8(payload).map_err(|_| ParseError::InvalidUtf8)?;

        let (request_line, rest) = if let Some(idx) = text.find("\r\n") {
            (&text[..idx], &text[idx + 2..])
        } else {
            return Err(ParseError::MissingStartLine);
        };

        let mut parts = request_line.split_whitespace();
        let method = parts.next().ok_or(ParseError::NotEnoughStartLineParts)?;
        if !HTTP_METHODS.iter().any(|&m| m == method) {
            return Err(ParseError::MissingStartLine);
        }
        let path = parts.next().ok_or(ParseError::NotEnoughStartLineParts)?;
        let version = parts.next().ok_or(ParseError::NotEnoughStartLineParts)?;

        let (headers, body) = parse_headers_and_body(rest)?;
        Ok(HTTPRequest {
            method,
            path,
            version,
            headers,
            body,
        })
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.as_str())
    }
}

/// Represents a parsed HTTP response (lifetime `'a` borrows from the original payload)
#[derive(Debug)]
pub struct HTTPResponse<'a> {
    pub version: &'a str,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: HashMap<String, String>,
    pub body: &'a [u8],
}

impl<'a> HTTPResponse<'a> {
    pub fn is_response(payload: &[u8]) -> bool {
        if let Ok(text) = str::from_utf8(payload) {
            text.starts_with("HTTP/")
        } else {
            false
        }
    }

    pub fn parse(payload: &'a [u8]) -> Result<Self, ParseError> {
        let text = str::from_utf8(payload).map_err(|_| ParseError::InvalidUtf8)?;

        let (status_line, rest) = if let Some(idx) = text.find("\r\n") {
            (&text[..idx], &text[idx + 2..])
        } else {
            return Err(ParseError::MissingStartLine);
        };

        let mut parts = status_line.split_whitespace();
        let version = parts.next().ok_or(ParseError::NotEnoughStartLineParts)?;
        if !version.starts_with("HTTP/") {
            return Err(ParseError::MissingStartLine);
        }
        let status_str = parts.next().ok_or(ParseError::NotEnoughStartLineParts)?;
        let reason_parts: Vec<&str> = parts.collect();
        if reason_parts.is_empty() {
            return Err(ParseError::NotEnoughStartLineParts);
        }
        let reason_phrase = reason_parts.join(" ");

        let status_code = match status_str.parse::<u16>() {
            Ok(n) => n,
            Err(_) => {
                return Err(ParseError::InvalidStatusCode(status_str.to_string()));
            }
        };

        let (headers, body) = parse_headers_and_body(rest)?;
        Ok(HTTPResponse {
            version,
            status_code,
            reason_phrase,
            headers,
            body,
        })
    }

    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(|v| v.as_str())
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

        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/");
        assert_eq!(parsed.version, "HTTP/1.0");

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

        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/submit");
        assert_eq!(parsed.version, "HTTP/1.1");

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

        assert_eq!(parsed.version, "HTTP/1.0");
        assert_eq!(parsed.status_code, 204);
        assert_eq!(parsed.reason_phrase, "No Content");

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

        assert_eq!(parsed.version, "HTTP/1.1");
        assert_eq!(parsed.status_code, 404);
        assert_eq!(parsed.reason_phrase, "Not Found");

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
