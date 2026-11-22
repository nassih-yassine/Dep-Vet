//! A stdio MCP server: newline-delimited JSON-RPC 2.0 on stdin/stdout.
//!
//! stdout carries only MCP messages; logging belongs on stderr. The transport
//! is pinned to the 2025-06-18 spec: one JSON object per line, no embedded
//! newlines, no `Content-Length` framing.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

pub const MAX_LINE_BYTES: usize = 1024 * 1024;
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

/// One newline-delimited message, or a refusal for a line over the limit.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadLine {
    Message(Vec<u8>),
    TooLong,
    Eof,
}

/// Read one line with a hard cap. The buffer never grows past `limit`; an
/// oversized line is drained to its newline and reported as `TooLong`.
pub fn read_line_bounded(input: &mut impl BufRead, limit: usize) -> std::io::Result<ReadLine> {
    let mut line = Vec::new();
    // Read at most `limit` content bytes plus a newline, and one byte to detect
    // an oversized line. The allocation is bounded even without a newline.
    let mut limited = std::io::Read::take(&mut *input, (limit + 2) as u64);
    let read = limited.read_until(b'\n', &mut line)?;
    if read == 0 {
        return Ok(ReadLine::Eof);
    }
    let newline = line.last() == Some(&b'\n');
    let content = if newline {
        &line[..line.len() - 1]
    } else {
        &line[..]
    };
    if content.len() > limit {
        if !newline {
            drain_to_newline(input)?;
        }
        return Ok(ReadLine::TooLong);
    }
    if newline || read < limit + 2 {
        // A complete line, or a final unterminated line at EOF.
        return Ok(ReadLine::Message(content.to_vec()));
    }
    // No newline and the capped read was full: the line is longer than the cap.
    drain_to_newline(input)?;
    Ok(ReadLine::TooLong)
}

fn drain_to_newline(input: &mut impl BufRead) -> std::io::Result<()> {
    loop {
        let buffer = input.fill_buf()?;
        if buffer.is_empty() {
            return Ok(());
        }
        match buffer.iter().position(|byte| *byte == b'\n') {
            Some(position) => {
                input.consume(position + 1);
                return Ok(());
            }
            None => {
                let length = buffer.len();
                input.consume(length);
            }
        }
    }
}

/// A tool call. `Err` is a JSON-RPC error code plus message.
pub type ToolResult = Result<Value, (i64, String)>;

pub fn serve(
    input: impl BufRead,
    output: &mut impl Write,
    mut call_tool: impl FnMut(&str, &Value) -> ToolResult,
) -> std::io::Result<()> {
    let mut input = input;
    loop {
        let response = match read_line_bounded(&mut input, MAX_LINE_BYTES)? {
            ReadLine::Eof => return Ok(()),
            ReadLine::TooLong => Some(error_response(
                Value::Null,
                -32600,
                "request line is too large",
            )),
            ReadLine::Message(bytes) => {
                let line = String::from_utf8_lossy(&bytes);
                let line = line.trim();
                if line.is_empty() {
                    None
                } else {
                    match serde_json::from_str::<Value>(line) {
                        Ok(request) => handle(&request, &mut call_tool),
                        Err(error) => Some(error_response(
                            Value::Null,
                            -32700,
                            &format!("invalid JSON: {error}"),
                        )),
                    }
                }
            }
        };
        if let Some(response) = response {
            serde_json::to_writer(&mut *output, &response)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
}

/// Handle one parsed message. `None` means "no response" (a notification).
pub fn handle(
    request: &Value,
    call_tool: &mut impl FnMut(&str, &Value) -> ToolResult,
) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str);
    let Some(method) = method else {
        return id.map(|id| error_response(id, -32600, "missing method"));
    };
    let is_notification = request.get("id").is_none();
    let result: Result<Value, (i64, String)> = match method {
        "initialize" => {
            let requested = request["params"]["protocolVersion"]
                .as_str()
                .unwrap_or(DEFAULT_PROTOCOL_VERSION);
            let version = if PROTOCOL_VERSIONS.contains(&requested) {
                requested
            } else {
                DEFAULT_PROTOCOL_VERSION
            };
            Ok(json!({
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "dep-vet",
                    "version": env!("CARGO_PKG_VERSION"),
                }
            }))
        }
        "initialized" | "notifications/initialized" => return None,
        "ping" => Ok(json!({})),
        "tools/list" => Ok(tools()),
        "tools/call" => {
            let name = match request["params"]["name"].as_str() {
                Some(name) => name,
                None => {
                    return id.map(|id| error_response(id, -32602, "missing tool name"));
                }
            };
            let arguments = request["params"]["arguments"].clone();
            let arguments = if arguments.is_null() {
                json!({})
            } else {
                arguments
            };
            call_tool(name, &arguments)
        }
        _ => Err((-32601, format!("unknown method '{method}'"))),
    };
    if is_notification {
        return None;
    }
    let id = id.unwrap_or(Value::Null);
    Some(match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err((code, message)) => error_response(id, code, &message),
    })
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message}
    })
}

pub fn tools() -> Value {
    json!({"tools": [
        {
            "name": "vet_package",
            "description": "Vet one package before installing it: advisories, typosquats, install scripts, freshness, and maintainers, with evidence links.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["ecosystem", "name"],
                "properties": {
                    "ecosystem": {
                        "type": "string",
                        "enum": ["npm", "pypi", "crates", "go", "jsr", "rubygems", "nuget", "maven", "composer"]
                    },
                    "name": {"type": "string"},
                    "version": {"type": "string"}
                }
            }
        },
        {
            "name": "vet_command",
            "description": "Vet the direct packages an install command names, using the same parser as the agent hook.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["command"],
                "properties": {"command": {"type": "string"}}
            }
        },
        {
            "name": "vet_lockfile_change",
            "description": "Audit the packages a lockfile change adds, comparing the working file with a git ref.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "required": ["lockfile"],
                "properties": {
                    "lockfile": {"type": "string"},
                    "base": {"type": "string"}
                }
            }
        }
    ]})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(lines: &[&str]) -> Vec<Value> {
        let mut out = Vec::new();
        serve(std::io::Cursor::new(lines.concat()), &mut out, |_, _| {
            Err((-32601, "no tools in this test".to_string()))
        })
        .unwrap();
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).expect("valid JSON line"))
            .collect()
    }

    fn no_tools(_: &str, _: &Value) -> ToolResult {
        Err((-32601, "no tools in this test".to_string()))
    }

    #[test]
    fn initialize_negotiates_a_supported_version() {
        let request = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}
        });
        let response = handle(&request, &mut no_tools).expect("response");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(response["result"]["serverInfo"]["name"], "dep-vet");
        assert!(response["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn unknown_protocol_version_gets_the_latest_supported() {
        let request = json!({
            "jsonrpc": "2.0", "id": 2, "method": "initialize",
            "params": {"protocolVersion": "1999-01-01", "capabilities": {},
                       "clientInfo": {"name": "test", "version": "1"}}
        });
        assert_eq!(
            handle(&request, &mut no_tools).unwrap()["result"]["protocolVersion"],
            "2025-06-18"
        );
    }

    #[test]
    fn notifications_get_no_response_and_unknown_methods_error() {
        assert!(
            handle(
                &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
                &mut no_tools
            )
            .is_none()
        );
        let response = handle(
            &json!({"jsonrpc": "2.0", "id": 3, "method": "nope"}),
            &mut no_tools,
        )
        .unwrap();
        assert_eq!(response["error"]["code"], -32601);
    }

    #[test]
    fn ping_answers_with_an_empty_result() {
        let response = handle(
            &json!({"jsonrpc": "2.0", "id": 4, "method": "ping"}),
            &mut no_tools,
        )
        .unwrap();
        assert_eq!(response["result"], json!({}));
    }

    #[test]
    fn bounded_reader_accepts_a_line_exactly_at_the_limit() {
        let line = format!("{}\n", "a".repeat(64));
        let mut input = std::io::Cursor::new(line.into_bytes());
        assert_eq!(
            read_line_bounded(&mut input, 64).unwrap(),
            ReadLine::Message(vec![b'a'; 64])
        );
        assert_eq!(read_line_bounded(&mut input, 64).unwrap(), ReadLine::Eof);
    }

    #[test]
    fn bounded_reader_rejects_an_oversized_line_and_recovers() {
        let mut bytes = "a".repeat(65).into_bytes();
        bytes.push(b'\n');
        bytes.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n");
        let mut input = std::io::Cursor::new(bytes);
        assert_eq!(
            read_line_bounded(&mut input, 64).unwrap(),
            ReadLine::TooLong
        );
        match read_line_bounded(&mut input, 64).unwrap() {
            ReadLine::Message(message) => {
                assert!(String::from_utf8(message).unwrap().contains("ping"))
            }
            other => panic!("expected the next message, got {other:?}"),
        }
    }

    #[test]
    fn bounded_reader_handles_a_huge_line_without_newline() {
        let mut bytes = vec![b'a'; 8 * MAX_LINE_BYTES];
        bytes.push(b'\n');
        bytes.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n");
        let mut input = std::io::Cursor::new(bytes);
        assert_eq!(
            read_line_bounded(&mut input, MAX_LINE_BYTES).unwrap(),
            ReadLine::TooLong
        );
        assert!(matches!(
            read_line_bounded(&mut input, MAX_LINE_BYTES).unwrap(),
            ReadLine::Message(_)
        ));
    }

    #[test]
    fn bounded_reader_accepts_a_final_unterminated_line() {
        let mut input = std::io::Cursor::new(b"{\"jsonrpc\":\"2.0\"}".to_vec());
        assert_eq!(
            read_line_bounded(&mut input, 64).unwrap(),
            ReadLine::Message(b"{\"jsonrpc\":\"2.0\"}".to_vec())
        );
        assert_eq!(read_line_bounded(&mut input, 64).unwrap(), ReadLine::Eof);
    }

    #[test]
    fn bounded_reader_reports_eof_with_nothing_buffered() {
        let mut input = std::io::Cursor::new(Vec::new());
        assert_eq!(read_line_bounded(&mut input, 64).unwrap(), ReadLine::Eof);
    }

    #[test]
    fn a_non_json_line_is_a_parse_error() {
        let output = run(&["not json\n"]);
        assert_eq!(output[0]["error"]["code"], -32700);
    }

    #[test]
    fn an_oversized_line_is_rejected_and_the_loop_continues() {
        let huge = "x".repeat(MAX_LINE_BYTES + 10);
        let output = run(&[
            &format!("{huge}\n"),
            "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n",
        ]);
        assert_eq!(output[0]["error"]["code"], -32600);
        assert_eq!(output[1]["id"], 7);
    }

    #[test]
    fn tools_are_three_strict_schemas() {
        let tools = tools();
        let list = tools["tools"].as_array().unwrap();
        assert_eq!(list.len(), 3);
        for tool in list {
            assert_eq!(tool["inputSchema"]["type"], "object");
            assert_eq!(tool["inputSchema"]["additionalProperties"], false);
            assert!(tool["description"].as_str().unwrap().len() > 20);
        }
        let package = list
            .iter()
            .find(|tool| tool["name"] == "vet_package")
            .unwrap();
        assert_eq!(
            package["inputSchema"]["required"],
            json!(["ecosystem", "name"])
        );
        assert!(
            package["inputSchema"]["properties"]["ecosystem"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "pypi")
        );
    }
}
