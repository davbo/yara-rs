//! Compute@Edge static content starter kit program.
mod config;

use fastly::http::{header, HeaderValue, Method, StatusCode};
use fastly::{Error, Request, Response};
use yara_macro::yara;

/// The entry point for your application.
///
/// This function is triggered when your service receives a client request. It could be used to
/// route based on the request properties (such as method or path), send the request to a backend,
/// make completely new requests, and/or generate synthetic responses.
///
/// If `main` returns an error, a 500 error response will be delivered to the client.
#[fastly::main]
fn main(mut req: Request) -> Result<Response, Error> {
    // Used later to generate CORS headers.
    // Usually you would want an allowlist of domains here, but this example allows any origin to make requests.
    let allowed_origins = match req.get_header(header::ORIGIN) {
        Some(val) => val.clone(),
        _ => HeaderValue::from_static("*"),
    };

    // Respond to CORS preflight requests.
    if req.get_method() == Method::OPTIONS
        && req.contains_header(header::ORIGIN)
        && (req.contains_header(header::ACCESS_CONTROL_REQUEST_HEADERS)
            || req.contains_header(header::ACCESS_CONTROL_REQUEST_METHOD))
    {
        return Ok(create_cors_response(allowed_origins));
    }

    // Only permit GET requests.
    if req.get_method() != Method::GET {
        return Ok(Response::from_body("Method not allowed")
            .with_status(StatusCode::METHOD_NOT_ALLOWED)
            .with_header(
                header::ALLOW,
                format!("{}, {}", Method::GET, Method::OPTIONS),
            ));
    }

    // Respond to requests for robots.txt.
    if req.get_path() == "/robots.txt" {
        return Ok(Response::from_body("User-agent: *\nAllow: /\n")
            .with_content_type(fastly::mime::TEXT_PLAIN));
    }

    // Remove the query string to improve cache hit ratio.
    req.remove_query();

    // Set the `Host` header to the bucket host rather than our C@E endpoint.
    req.set_header(
        header::HOST,
        format!("{}.{}", config::BUCKET_NAME, config::BUCKET_HOST),
    );

    // Copy the modified client request to create a backend request.
    let bereq = req.clone_without_body();

    // Send the request to the backend and assign its response to `beresp`.
    let mut beresp = bereq.send(config::BACKEND_NAME)?;

    filter_headers(&mut beresp);

    let body = beresp.into_body();
    let body_bytes = body.into_bytes();

    let rules = yara!(
        "
      rule cryptonight
      {
        meta:
          description = \"Crytonight Miner\"
        strings:
          $a = { 00 61 73 6D }
          $b = { 63 72 79 70 74 6F 6E 69 67 68 74 5F 68 61 73 68 }
        condition:
          $a and $b
      }
"
    );

    let found = rules.matches(&body_bytes);
    return if found {
        Ok(Response::from_status(StatusCode::NOT_FOUND))
    } else {
        Ok(Response::from_body(body_bytes))
    };
}

/// Removes all headers but those defined in `ALLOWED_HEADERS` from a response.
fn filter_headers(resp: &mut Response) {
    let to_remove: Vec<_> = resp
        .get_header_names()
        .filter(|header| !config::ALLOWED_HEADERS.contains(header))
        .cloned()
        .collect();

    for header in to_remove {
        resp.remove_header(header);
    }
}

/// Create a response to a CORS preflight request.
fn create_cors_response(allowed_origins: HeaderValue) -> Response {
    Response::from_status(StatusCode::NO_CONTENT)
        .with_header(header::ACCESS_CONTROL_ALLOW_ORIGIN, allowed_origins)
        .with_header(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            "GET,HEAD,POST,OPTIONS",
        )
        .with_header(header::ACCESS_CONTROL_MAX_AGE, "86400")
        .with_header(header::CACHE_CONTROL, "public, max-age=86400")
}
