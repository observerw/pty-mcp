use rmcp::{
    ErrorData, Json, handler::server::wrapper::Parameters, model::CallToolResult, tool, tool_router,
};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_value};

use crate::{
    AppState, SpawnSessionRequest,
    app::{
        SshConnectRequest as AppSshConnectRequest, SshDirectoryEntryType,
        SshDisconnectRequest as AppSshDisconnectRequest, SshExecRequest as AppSshExecRequest,
        SshMountRequest as AppSshMountRequest, SshRunRequest as AppSshRunRequest,
        SshSessionSpawnRequest as AppSshSessionSpawnRequest,
        SshTunnelCloseRequest as AppSshTunnelCloseRequest,
        SshTunnelOpenRequest as AppSshTunnelOpenRequest, SshUnmountRequest as AppSshUnmountRequest,
    },
    buffer::{BufferReadPage, BufferReadRequest, BufferView},
    session::{ReadView, SessionId, SessionStatus, SessionSummary, SessionTransport, SignalKind},
    ssh::{
        SshAuthKind, SshConnectionId, SshConnectionStatus, SshConnectionSummary, SshMountBackend,
        SshMountId, SshMountStatus, SshMountSummary, SshTarget, SshTunnelId, SshTunnelKind,
        SshTunnelStatus, SshTunnelSummary,
    },
};

use super::service::PtyMcpServer;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
#[serde(rename_all = "snake_case")]
pub enum LineNumberMode {
    None,
    Embedded,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtySpawnRequest {
    #[schemars(description = "Executable or shell command to start in the new PTY session.")]
    pub command: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(description = "Argument vector passed to the spawned command.")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Working directory for the spawned process.")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Environment variable overrides. Values must be scalar JSON values.")]
    pub env: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Optional short title for display in session listings.")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Optional human-readable note stored with the session. Defaults to a generated summary."
    )]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Milliseconds to wait for first output before returning initial_output. Default: 0. Only used when capture_limit is set."
    )]
    pub capture_wait_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Maximum number of output lines to include in initial_output. This is the only switch that enables initial_output."
    )]
    pub capture_limit: Option<usize>,
    #[schemars(
        description = "Read view for initial_output. Allowed values: plain | ansi | raw. Default: plain. Providing this without capture_limit is invalid."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_view: Option<ReadView>,
    #[schemars(
        description = "How to include line numbers in initial_output.text. Allowed values: none | embedded. Default: none. raw output_view cannot be combined with embedded. Providing this without capture_limit is invalid."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number_mode: Option<LineNumberMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyOutputPage {
    pub offset: usize,
    pub returned: usize,
    pub has_more: bool,
    pub total_lines: usize,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtySpawnResponse {
    pub session_id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_output: Option<PtyOutputPage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyWriteRequest {
    pub session_id: SessionId,
    pub data: String,
    #[schemars(description = "Write mode. Allowed values: plain | escaped. Default: plain.")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<WriteMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[schemars(inline)]
#[serde(rename_all = "snake_case")]
pub enum WriteMode {
    Plain,
    Escaped,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyWriteResponse {
    pub session_id: SessionId,
    pub bytes_written: usize,
    pub accepted: bool,
    pub status: SessionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyReadRequest {
    pub session_id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Zero-based starting line offset. Default: 0.")]
    pub offset: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Maximum number of lines to return. Default: server read limit.")]
    pub limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Optional regular expression applied after view selection.")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Whether regex matching should ignore case. Default: false.")]
    pub ignore_case: Option<bool>,
    #[schemars(
        description = "Read view. Allowed values: plain | ansi | raw. Default: plain. raw output_view cannot be combined with embedded line_number_mode."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_view: Option<ReadView>,
    #[schemars(
        description = "How to include line numbers in page.text. Allowed values: none | embedded. Default: none. embedded prefixes each returned line as <line_number>\\t<text>. raw output_view cannot be combined with embedded."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number_mode: Option<LineNumberMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyReadResponse {
    pub session_id: SessionId,
    pub status: SessionStatus,
    pub page: PtyOutputPage,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyListResponse {
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConnectRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_path: Option<String>,
    pub auth_kind: SshAuthKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_host_key: Option<bool>,
}

impl JsonSchema for SshConnectRequest {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SshConnectRequest".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "object",
            "properties": {
                "host_alias": {
                    "type": ["string", "null"],
                    "description": "SSH config alias to connect to. Required when auth_kind=config_alias. Provide this or host (at least one must be set)."
                },
                "host": {
                    "type": ["string", "null"],
                    "description": "SSH hostname to connect to. Provide this or host_alias (at least one must be set)."
                },
                "port": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                    "maximum": 65535,
                    "description": "SSH port. Default: 22."
                },
                "user": {
                    "type": ["string", "null"],
                    "description": "Remote username."
                },
                "identity_path": {
                    "type": ["string", "null"],
                    "description": "Absolute path to the SSH identity file. Required when auth_kind=identity_file."
                },
                "auth_kind": {
                    "type": "string",
                    "enum": ["ssh_agent", "identity_file", "config_alias"],
                    "description": "Authentication mode. Allowed values: ssh_agent | identity_file | config_alias. This field is required and never inferred."
                },
                "title": {
                    "type": ["string", "null"],
                    "description": "Optional short title for display in connection listings."
                },
                "description": {
                    "type": ["string", "null"],
                    "description": "Optional human-readable note stored with the connection. Defaults to a generated summary."
                },
                "verify_host_key": {
                    "type": ["boolean", "null"],
                    "description": "Whether SSH host key verification should remain enabled. Default: true."
                }
            },
            "required": ["auth_kind"]
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshConnectResponse {
    pub connection_id: SshConnectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub status: SshConnectionStatus,
    pub target: SshTarget,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub reused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshListResponse {
    pub connections: Vec<SshConnectionSummary>,
    pub mounts: Vec<SshMountSummaryView>,
    pub tunnels: Vec<SshTunnelSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshMountSummaryView {
    pub mount_id: SshMountId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub connection_id: SshConnectionId,
    pub target_summary: String,
    pub status: SshMountStatus,
    pub backend: SshMountBackend,
    pub target_path: String,
    pub remote_path: String,
    pub read_only: bool,
    pub mounted_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshTunnelOpenRequest {
    pub connection_id: SshConnectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Local bind address for the forwarded port. Default: 127.0.0.1. Non-loopback addresses must be allowed by policy."
    )]
    pub bind_host: Option<String>,
    #[schemars(
        description = "Local listening port. Set to 0 to let the server choose an available port."
    )]
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote host to connect to from the SSH target. Default: 127.0.0.1.")]
    pub remote_host: Option<String>,
    #[schemars(description = "Remote TCP port to forward to.")]
    pub remote_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Optional short title for display in tunnel listings.")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Optional human-readable note stored with the tunnel. Defaults to a generated summary."
    )]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshTunnelOpenResponse {
    pub tunnel_id: SshTunnelId,
    pub connection_id: SshConnectionId,
    pub kind: SshTunnelKind,
    pub status: SshTunnelStatus,
    pub bind_host: String,
    pub local_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub reused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshTunnelCloseRequest {
    pub tunnel_id: SshTunnelId,
    #[schemars(description = "Force tunnel shutdown immediately. Default: false.")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshTunnelCloseResponse {
    pub tunnel_id: SshTunnelId,
    pub previous_status: SshTunnelStatus,
    pub current_status: SshTunnelStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshSessionSpawnRequest {
    pub connection_id: SshConnectionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Command to run on the remote host. Omit to open the remote shell directly."
    )]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(description = "Argument vector passed to the remote command.")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote working directory. Must be an absolute path, ~, or ~/...")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote environment overrides. Values must be scalar JSON values.")]
    pub env: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote shell binary to invoke when shell wrapping is needed.")]
    pub shell: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Whether to request an interactive remote shell. Default: true.")]
    pub interactive: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Whether to start the remote shell as a login shell. Default: false."
    )]
    pub login: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Optional short title for display in session listings.")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Optional human-readable note stored with the session. Defaults to a generated summary."
    )]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Milliseconds to wait for first output before returning initial_output. Default: 0. Only used when capture_limit is set."
    )]
    pub capture_wait_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Maximum number of output lines to include in initial_output. This is the only switch that enables initial_output."
    )]
    pub capture_limit: Option<usize>,
    #[schemars(
        description = "Read view for initial_output. Allowed values: plain | ansi | raw. Default: plain. Providing this without capture_limit is invalid."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_view: Option<ReadView>,
    #[schemars(
        description = "How to include line numbers in initial_output.text. Allowed values: none | embedded. Default: none. raw output_view cannot be combined with embedded. Providing this without capture_limit is invalid."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number_mode: Option<LineNumberMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshExecRequest {
    pub connection_id: SshConnectionId,
    #[schemars(description = "Shell script to execute remotely. Must not be empty.")]
    pub script: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote working directory. Must be an absolute path, ~, or ~/...")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote environment overrides. Values must be scalar JSON values.")]
    pub env: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote shell binary used to execute the script.")]
    pub shell: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Whether to start the remote shell as a login shell. Default: false."
    )]
    pub login: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Optional short title for display in session listings.")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Optional human-readable note stored with the session. Defaults to a generated summary."
    )]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Milliseconds to wait for completion before returning completed/exit fields. If omitted, return immediately after spawn."
    )]
    pub wait_timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Maximum number of output lines to include in initial_output. This is the only switch that enables initial_output."
    )]
    pub capture_limit: Option<usize>,
    #[schemars(
        description = "Read view for initial_output. Allowed values: plain | ansi | raw. Default: plain. Providing this without capture_limit is invalid."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_view: Option<ReadView>,
    #[schemars(
        description = "How to include line numbers in initial_output.text. Allowed values: none | embedded. Default: none. raw output_view cannot be combined with embedded. Providing this without capture_limit is invalid."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number_mode: Option<LineNumberMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshRunRequest {
    pub connection_id: SshConnectionId,
    #[schemars(description = "Shell script to execute remotely. Must not be empty.")]
    pub script: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote working directory. Must be an absolute path, ~, or ~/...")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote environment overrides. Values must be scalar JSON values.")]
    pub env: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Remote shell binary used to execute the script.")]
    pub shell: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Whether to start the remote shell as a login shell. Default: false."
    )]
    pub login: Option<bool>,
    #[schemars(description = "Maximum combined stdout+stderr bytes to capture. Default: 262144.")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Milliseconds before aborting the remote command. If omitted, wait until completion."
    )]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshSessionSpawnResponse {
    pub connection_id: SshConnectionId,
    pub session_id: SessionId,
    pub transport: SessionTransport,
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_cwd: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_output: Option<PtyOutputPage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshExecResponse {
    pub connection_id: SshConnectionId,
    pub session_id: SessionId,
    pub transport: SessionTransport,
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_cwd: Option<String>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_signal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_output: Option<PtyOutputPage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshRunResponse {
    pub connection_id: SshConnectionId,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshMountRequest {
    pub connection_id: SshConnectionId,
    #[schemars(description = "Remote path to mount. Must be an absolute path, ~, or ~/...")]
    pub remote_path: String,
    #[schemars(
        description = "Local mount target path. Must be absolute and inside the configured managed or allowed mount roots."
    )]
    pub target_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Mount the remote filesystem read-only. Default: false.")]
    pub read_only: Option<bool>,
    #[schemars(
        description = "Mount backend. Allowed values: sshfs. Default: automatic backend selection."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<SshMountBackend>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Create the target_path directory if it does not already exist. Default: true."
    )]
    pub create_target: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Optional short title for display in mount listings.")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Optional human-readable note stored with the mount. Defaults to a generated summary."
    )]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshMountResponse {
    pub mount_id: SshMountId,
    pub connection_id: SshConnectionId,
    pub remote_path: String,
    pub target_path: String,
    pub backend: SshMountBackend,
    pub status: SshMountStatus,
    pub mounted_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshUnmountRequest {
    pub mount_id: SshMountId,
    #[schemars(
        description = "Force unmount when the platform backend supports it. Default: false."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
    #[schemars(
        description = "Remove target_path after unmount only when the server determines cleanup is allowed. Default: false."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_target: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshUnmountResponse {
    pub mount_id: SshMountId,
    pub previous_status: SshMountStatus,
    pub current_status: SshMountStatus,
    pub target_path: String,
    pub cleanup_target: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshDisconnectRequest {
    pub connection_id: SshConnectionId,
    #[schemars(
        description = "Force disconnect even when sessions are still running. Active mounts still require cleanup_mounts=true. Default: false."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,
    #[schemars(
        description = "Unmount active SSH mounts during a forced disconnect. Default: false."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_mounts: Option<bool>,
    #[schemars(
        description = "Close active SSH tunnels during a forced disconnect. Default: false."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cleanup_tunnels: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshDisconnectResponse {
    pub connection_id: SshConnectionId,
    pub previous_status: SshConnectionStatus,
    pub current_status: SshConnectionStatus,
    pub closed_sessions: usize,
    pub closed_mounts: usize,
    pub closed_tunnels: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshReadFileRequest {
    pub connection_id: SshConnectionId,
    #[schemars(description = "Remote file path. Must be an absolute path, ~, or ~/...")]
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Maximum UTF-8 file size to read, in bytes. Allowed range: 1..=524288. Default: 131072."
    )]
    pub max_bytes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshReadFileResponse {
    pub connection_id: SshConnectionId,
    pub path: String,
    pub content: String,
    pub bytes_read: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshWriteFileRequest {
    pub connection_id: SshConnectionId,
    #[schemars(description = "Remote file path. Must be an absolute path, ~, or ~/...")]
    pub path: String,
    #[schemars(description = "UTF-8 file content to write. Maximum size: 262144 bytes.")]
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Append to the file instead of overwriting it. Default: false.")]
    pub append: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Create parent directories before writing. Default: false.")]
    pub create_parents: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshWriteFileResponse {
    pub connection_id: SshConnectionId,
    pub path: String,
    pub bytes_written: usize,
    pub append: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SshDirectoryEntryTypeView {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshDirectoryEntryView {
    pub name: String,
    pub path: String,
    pub entry_type: SshDirectoryEntryTypeView,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshListDirRequest {
    pub connection_id: SshConnectionId,
    #[schemars(description = "Remote directory path. Must be an absolute path, ~, or ~/...")]
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Whether hidden entries should be included. Default: false.")]
    pub include_hidden: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshListDirResponse {
    pub connection_id: SshConnectionId,
    pub path: String,
    pub entries: Vec<SshDirectoryEntryView>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshMkdirRequest {
    pub connection_id: SshConnectionId,
    #[schemars(description = "Remote directory path. Must be an absolute path, ~, or ~/...")]
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(description = "Create parent directories as needed. Default: false.")]
    pub create_parents: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SshMkdirResponse {
    pub connection_id: SshConnectionId,
    pub path: String,
    pub create_parents: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyKillRequest {
    pub session_id: SessionId,
    #[schemars(
        description = "Signal to send to the PTY process. Allowed values: sigint | sigterm | sigkill. Default: sigterm."
    )]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<SignalKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Remove the session metadata and buffered output after kill. Default: false."
    )]
    pub cleanup_session: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyKillResponse {
    pub session_id: SessionId,
    pub previous_status: SessionStatus,
    pub current_status: SessionStatus,
    pub cleanup_session: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyWaitRequest {
    pub session_id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(
        description = "Maximum time to wait before returning. If omitted, wait until the session exits."
    )]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PtyWaitResponse {
    pub completed: bool,
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_signal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_output_preview: Option<String>,
}

fn structured<T: Serialize>(value: &T) -> Result<CallToolResult, rmcp::ErrorData> {
    let value = to_value(value).map_err(|error| {
        ErrorData::internal_error(format!("failed to serialize tool result: {error}"), None)
    })?;
    Ok(CallToolResult::structured(value))
}

// `ErrorData` is reserved for MCP protocol failures such as invalid params or
// serialization issues. Tool execution failures must flow through
// `CallToolResult` with `is_error = true`.
fn tool_execution_error(error: anyhow::Error) -> CallToolResult {
    CallToolResult::structured_error(json!({
        "message": error.to_string(),
    }))
}

fn invalid_params(message: impl Into<String>) -> ErrorData {
    ErrorData::invalid_params(message.into(), None)
}

#[tool_router(router = tool_router, vis = "pub(crate)")]
impl PtyMcpServer {
    #[tool(
        name = "pty_spawn",
        description = "Create a new PTY session without waiting for the process to finish.",
        execution(task_support = "optional")
    )]
    pub async fn pty_spawn(
        &self,
        Parameters(request): Parameters<PtySpawnRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let capture_options = validate_capture_options(
            request.capture_limit,
            request.capture_wait_ms,
            request.output_view,
            request.line_number_mode,
        )?;
        match self
            .app()
            .local()
            .spawn_session(SpawnSessionRequest {
                command: request.command,
                args: request.args,
                cwd: request.cwd,
                env: request.env,
                title: request.title,
                description: request.description,
            })
            .await
        {
            Ok(summary) => {
                let initial_output = if let Some(options) = capture_options {
                    capture_initial_output(
                        self.app(),
                        &summary.session_id,
                        options.capture_wait_ms,
                        options.limit,
                        options.view,
                        options.line_number_mode,
                    )
                    .await
                    .map_err(|error| ErrorData::internal_error(error.to_string(), None))?
                } else {
                    None
                };

                let latest = self
                    .app()
                    .local()
                    .get_session(&summary.session_id)
                    .unwrap_or(summary);

                structured(&PtySpawnResponse {
                    session_id: latest.session_id,
                    title: latest.title,
                    status: latest.status,
                    pid: latest.pid,
                    cwd: latest.cwd,
                    started_at: latest.started_at,
                    initial_output,
                })
            }
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "pty_write",
        description = "Send input into a running PTY session.",
        execution(task_support = "optional")
    )]
    pub async fn pty_write(
        &self,
        Parameters(request): Parameters<PtyWriteRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .local()
            .write_session(
                &request.session_id,
                &request.data,
                matches!(request.mode.unwrap_or(WriteMode::Plain), WriteMode::Escaped),
            )
            .await
        {
            Ok(outcome) => structured(&PtyWriteResponse {
                session_id: outcome.session_id,
                bytes_written: outcome.bytes_written,
                accepted: outcome.accepted,
                status: outcome.status,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "pty_read",
        description = "Read PTY output with pagination, optional filtering, and view selection.",
        execution(task_support = "optional")
    )]
    pub async fn pty_read(
        &self,
        Parameters(request): Parameters<PtyReadRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let view = request.output_view.unwrap_or(ReadView::Plain);
        let line_number_mode = request.line_number_mode.unwrap_or(LineNumberMode::None);
        validate_line_number_mode(view.clone(), line_number_mode)?;
        match self.app().local().read_session(
            &request.session_id,
            &BufferReadRequest {
                offset: request.offset.unwrap_or(0),
                limit: request
                    .limit
                    .unwrap_or(self.app().config().default_read_limit)
                    .max(1),
                pattern: request.pattern,
                ignore_case: request.ignore_case.unwrap_or(false),
                view: resolve_buffer_view(view),
            },
        ) {
            Ok(page) => {
                let status = self
                    .app()
                    .local()
                    .get_session(&request.session_id)
                    .map(|summary| summary.status)
                    .unwrap_or(SessionStatus::Exited);
                structured(&PtyReadResponse {
                    session_id: request.session_id,
                    status,
                    page: render_output_page(page, line_number_mode),
                })
            }
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "pty_list",
        description = "List known PTY sessions without returning large log payloads.",
        execution(task_support = "optional")
    )]
    pub async fn pty_list(&self) -> Json<PtyListResponse> {
        Json(PtyListResponse {
            sessions: enrich_sessions_with_ssh_context(self.app()),
        })
    }

    #[tool(
        name = "ssh_connect",
        description = "Create or reuse an SSH connection handle.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_connect(
        &self,
        Parameters(request): Parameters<SshConnectRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        if matches!(request.auth_kind, SshAuthKind::ConfigAlias)
            && request
                .host_alias
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            return Err(invalid_params(
                "host_alias is required when auth_kind=config_alias",
            ));
        }
        if matches!(request.auth_kind, SshAuthKind::IdentityFile)
            && request
                .identity_path
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .is_none()
        {
            return Err(invalid_params(
                "identity_path is required when auth_kind=identity_file",
            ));
        }
        if let Some(identity_path) = request.identity_path.as_deref() {
            let path = std::path::Path::new(identity_path.trim());
            if matches!(request.auth_kind, SshAuthKind::IdentityFile) && !path.is_absolute() {
                return Err(invalid_params(format!(
                    "identity_path must be an absolute path: identity_path={}",
                    path.display()
                )));
            }
        }
        match self
            .app()
            .ssh()
            .connect(AppSshConnectRequest {
                host_alias: request.host_alias,
                host: request.host,
                user: request.user,
                port: request.port,
                auth_kind: request.auth_kind,
                identity_path: request.identity_path,
                title: request.title,
                description: request.description,
                verify_host_key: request.verify_host_key.unwrap_or(true),
            })
            .await
        {
            Ok(result) => structured(&SshConnectResponse {
                connection_id: result.connection.connection_id,
                title: result.connection.title,
                status: result.connection.status,
                target: result.connection.target,
                started_at: result.connection.started_at,
                reused: result.reused,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_list",
        description = "List SSH connection and mount summaries.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_list(&self) -> Json<SshListResponse> {
        let result = self.app().ssh().list();
        Json(SshListResponse {
            connections: result.connections,
            mounts: result.mounts.into_iter().map(Into::into).collect(),
            tunnels: result.tunnels,
        })
    }

    #[tool(
        name = "ssh_tunnel_open",
        description = "Open or reuse a persistent local SSH tunnel over an existing SSH connection.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_tunnel_open(
        &self,
        Parameters(request): Parameters<SshTunnelOpenRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .open_tunnel(AppSshTunnelOpenRequest {
                connection_id: request.connection_id.clone(),
                bind_host: request.bind_host,
                local_port: request.local_port,
                remote_host: request.remote_host,
                remote_port: request.remote_port,
                title: request.title,
                description: request.description,
            })
            .await
        {
            Ok(result) => structured(&SshTunnelOpenResponse {
                tunnel_id: result.tunnel.tunnel_id,
                connection_id: result.tunnel.connection_id,
                kind: result.tunnel.kind,
                status: result.tunnel.status,
                bind_host: result.tunnel.bind_host,
                local_port: result.tunnel.local_port,
                remote_host: result.tunnel.remote_host,
                remote_port: result.tunnel.remote_port,
                started_at: result.tunnel.started_at,
                reused: result.reused,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_session_spawn",
        description = "Spawn a remote SSH-backed PTY session that reuses an existing SSH connection.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_session_spawn(
        &self,
        Parameters(request): Parameters<SshSessionSpawnRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let capture_options = validate_capture_options(
            request.capture_limit,
            request.capture_wait_ms,
            request.output_view,
            request.line_number_mode,
        )?;
        match self
            .app()
            .ssh()
            .session_spawn(AppSshSessionSpawnRequest {
                connection_id: request.connection_id.clone(),
                command: request.command,
                args: request.args,
                cwd: request.cwd,
                env: request.env,
                shell: request.shell,
                interactive: request.interactive.unwrap_or(true),
                login: request.login.unwrap_or(false),
                title: request.title,
                description: request.description,
            })
            .await
        {
            Ok(spawned) => {
                let initial_output = if let Some(options) = capture_options {
                    match capture_initial_output(
                        self.app(),
                        &spawned.session_id,
                        options.capture_wait_ms,
                        options.limit,
                        options.view,
                        options.line_number_mode,
                    )
                    .await
                    {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            return Ok::<CallToolResult, ErrorData>(tool_execution_error(error));
                        }
                    }
                } else {
                    None
                };

                let latest = self
                    .app()
                    .local()
                    .get_session(&spawned.session_id)
                    .unwrap_or(spawned);

                structured(&SshSessionSpawnResponse {
                    connection_id: request.connection_id,
                    session_id: latest.session_id,
                    transport: latest.transport,
                    status: latest.status,
                    target_summary: latest.target_summary,
                    remote_cwd: latest.remote_cwd,
                    started_at: latest.started_at,
                    initial_output,
                })
            }
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_exec",
        description = "Run a shell script on an existing SSH connection and keep the result attached to a PTY-backed session.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_exec(
        &self,
        Parameters(request): Parameters<SshExecRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        let wait_timeout_ms = request.wait_timeout_ms;
        let capture_options = validate_capture_options(
            request.capture_limit,
            None,
            request.output_view,
            request.line_number_mode,
        )?;
        match self
            .app()
            .ssh()
            .exec(AppSshExecRequest {
                connection_id: request.connection_id.clone(),
                script: request.script,
                cwd: request.cwd,
                env: request.env,
                shell: request.shell,
                login: request.login.unwrap_or(false),
                title: request.title,
                description: request.description,
            })
            .await
        {
            Ok(spawned) => {
                let wait_outcome = if let Some(timeout_ms) = wait_timeout_ms {
                    match self
                        .app()
                        .local()
                        .wait_session(
                            &spawned.session_id,
                            Some(std::time::Duration::from_millis(timeout_ms)),
                        )
                        .await
                    {
                        Ok(outcome) => Some(outcome),
                        Err(error) => {
                            return Ok::<CallToolResult, ErrorData>(tool_execution_error(error));
                        }
                    }
                } else {
                    None
                };

                let latest = self
                    .app()
                    .local()
                    .get_session(&spawned.session_id)
                    .unwrap_or(spawned);

                let initial_output = if let Some(options) = capture_options {
                    match capture_initial_output(
                        self.app(),
                        &latest.session_id,
                        0,
                        options.limit,
                        options.view,
                        options.line_number_mode,
                    )
                    .await
                    {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            return Ok::<CallToolResult, ErrorData>(tool_execution_error(error));
                        }
                    }
                } else {
                    None
                };

                structured(&SshExecResponse {
                    connection_id: request.connection_id,
                    session_id: latest.session_id,
                    transport: latest.transport,
                    status: latest.status,
                    target_summary: latest.target_summary,
                    remote_cwd: latest.remote_cwd,
                    started_at: latest.started_at,
                    completed: wait_outcome.as_ref().map(|outcome| outcome.completed),
                    exit_code: wait_outcome
                        .as_ref()
                        .and_then(|outcome| outcome.exit_info.as_ref())
                        .and_then(|info| info.exit_code),
                    exit_signal: wait_outcome
                        .as_ref()
                        .and_then(|outcome| outcome.exit_info.as_ref())
                        .and_then(|info| info.exit_signal.clone()),
                    initial_output,
                })
            }
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_run",
        description = "Run a one-shot shell script on an existing SSH connection and return stdout, stderr, and exit status directly.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_run(
        &self,
        Parameters(request): Parameters<SshRunRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .run(AppSshRunRequest {
                connection_id: request.connection_id.clone(),
                script: request.script,
                cwd: request.cwd,
                env: request.env,
                shell: request.shell,
                login: request.login.unwrap_or(false),
                max_output_bytes: request.max_output_bytes,
                timeout_ms: request.timeout_ms,
            })
            .await
        {
            Ok(result) => structured(&SshRunResponse {
                connection_id: result.connection_id,
                success: result.success,
                exit_code: result.exit_code,
                exit_signal: result.exit_signal,
                stdout: result.stdout,
                stderr: result.stderr,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_mount",
        description = "Mount a remote SSH path into a local directory via sshfs.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_mount(
        &self,
        Parameters(request): Parameters<SshMountRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .mount(AppSshMountRequest {
                connection_id: request.connection_id,
                remote_path: request.remote_path,
                target_path: request.target_path,
                read_only: request.read_only.unwrap_or(false),
                backend: request.backend,
                create_target: request.create_target.unwrap_or(true),
                title: request.title,
                description: request.description,
            })
            .await
        {
            Ok(mount) => structured(&SshMountResponse {
                mount_id: mount.mount_id,
                connection_id: mount.connection_id,
                remote_path: mount.remote_path,
                target_path: mount.local_path,
                backend: mount.backend,
                status: mount.status,
                mounted_at: mount.mounted_at,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_unmount",
        description = "Unmount an sshfs-backed SSH mount.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_unmount(
        &self,
        Parameters(request): Parameters<SshUnmountRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .unmount(AppSshUnmountRequest {
                mount_id: request.mount_id,
                force: request.force.unwrap_or(false),
                cleanup_target: request.cleanup_target.unwrap_or(false),
            })
            .await
        {
            Ok(result) => structured(&SshUnmountResponse {
                mount_id: result.mount.mount_id,
                previous_status: result.previous_status,
                current_status: result.mount.status,
                target_path: result.mount.local_path,
                cleanup_target: result.cleanup_target,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_tunnel_close",
        description = "Close a persistent SSH tunnel.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_tunnel_close(
        &self,
        Parameters(request): Parameters<SshTunnelCloseRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .close_tunnel(AppSshTunnelCloseRequest {
                tunnel_id: request.tunnel_id,
                force: request.force.unwrap_or(false),
            })
            .await
        {
            Ok(result) => structured(&SshTunnelCloseResponse {
                tunnel_id: result.tunnel_id,
                previous_status: result.previous_status,
                current_status: result.current_status,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_disconnect",
        description = "Disconnect an SSH connection and optionally clean up related sessions and mounts.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_disconnect(
        &self,
        Parameters(request): Parameters<SshDisconnectRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .disconnect(AppSshDisconnectRequest {
                connection_id: request.connection_id,
                force: request.force.unwrap_or(false),
                cleanup_mounts: request.cleanup_mounts.unwrap_or(false),
                cleanup_tunnels: request.cleanup_tunnels.unwrap_or(false),
            })
            .await
        {
            Ok(result) => structured(&SshDisconnectResponse {
                connection_id: result.connection_id,
                previous_status: result.previous_status,
                current_status: result.current_status,
                closed_sessions: result.closed_sessions,
                closed_mounts: result.closed_mounts,
                closed_tunnels: result.closed_tunnels,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_read_file",
        description = "Read a UTF-8 text file over an existing SSH connection.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_read_file(
        &self,
        Parameters(request): Parameters<SshReadFileRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .read_file(
                &request.connection_id,
                &request.path,
                request.max_bytes.unwrap_or(128 * 1024),
            )
            .await
        {
            Ok(result) => structured(&SshReadFileResponse {
                connection_id: result.connection_id,
                path: result.path,
                content: result.content,
                bytes_read: result.bytes_read,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_write_file",
        description = "Write a UTF-8 text file over an existing SSH connection.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_write_file(
        &self,
        Parameters(request): Parameters<SshWriteFileRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .write_file(
                &request.connection_id,
                &request.path,
                &request.content,
                request.append.unwrap_or(false),
                request.create_parents.unwrap_or(false),
            )
            .await
        {
            Ok(result) => structured(&SshWriteFileResponse {
                connection_id: result.connection_id,
                path: result.path,
                bytes_written: result.bytes_written,
                append: result.append,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_list_dir",
        description = "List one remote directory level over an existing SSH connection.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_list_dir(
        &self,
        Parameters(request): Parameters<SshListDirRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .list_directory(
                &request.connection_id,
                &request.path,
                request.include_hidden.unwrap_or(false),
            )
            .await
        {
            Ok(result) => structured(&SshListDirResponse {
                connection_id: result.connection_id,
                path: result.path,
                entries: result
                    .entries
                    .into_iter()
                    .map(|entry| SshDirectoryEntryView {
                        name: entry.name,
                        path: entry.path,
                        entry_type: match entry.entry_type {
                            SshDirectoryEntryType::File => SshDirectoryEntryTypeView::File,
                            SshDirectoryEntryType::Directory => {
                                SshDirectoryEntryTypeView::Directory
                            }
                            SshDirectoryEntryType::Symlink => SshDirectoryEntryTypeView::Symlink,
                            SshDirectoryEntryType::Other => SshDirectoryEntryTypeView::Other,
                        },
                    })
                    .collect(),
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "ssh_mkdir",
        description = "Create a remote directory over an existing SSH connection.",
        execution(task_support = "optional")
    )]
    pub async fn ssh_mkdir(
        &self,
        Parameters(request): Parameters<SshMkdirRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .ssh()
            .mkdir(
                &request.connection_id,
                &request.path,
                request.create_parents.unwrap_or(false),
            )
            .await
        {
            Ok(result) => structured(&SshMkdirResponse {
                connection_id: result.connection_id,
                path: result.path,
                create_parents: result.create_parents,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "pty_kill",
        description = "Stop a PTY session and optionally clean up its metadata and buffered output.",
        execution(task_support = "optional")
    )]
    pub async fn pty_kill(
        &self,
        Parameters(request): Parameters<PtyKillRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .local()
            .kill_session(
                &request.session_id,
                request.signal.unwrap_or(SignalKind::Sigterm),
                request.cleanup_session.unwrap_or(false),
            )
            .await
        {
            Ok(outcome) => structured(&PtyKillResponse {
                session_id: outcome.session_id,
                previous_status: outcome.previous_status,
                current_status: outcome.current_status,
                cleanup_session: outcome.cleanup,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }

    #[tool(
        name = "pty_wait",
        description = "Wait for a PTY session to exit without requiring host task support.",
        execution(task_support = "optional")
    )]
    pub async fn pty_wait(
        &self,
        Parameters(request): Parameters<PtyWaitRequest>,
    ) -> Result<CallToolResult, rmcp::ErrorData> {
        match self
            .app()
            .local()
            .wait_session(
                &request.session_id,
                request.timeout_ms.map(std::time::Duration::from_millis),
            )
            .await
        {
            Ok(outcome) => structured(&PtyWaitResponse {
                completed: outcome.completed,
                status: outcome.status,
                exit_code: outcome.exit_info.as_ref().and_then(|info| info.exit_code),
                exit_signal: outcome
                    .exit_info
                    .as_ref()
                    .and_then(|info| info.exit_signal.clone()),
                last_output_preview: outcome.last_output_preview,
            }),
            Err(error) => Ok::<CallToolResult, ErrorData>(tool_execution_error(error)),
        }
    }
}

pub fn seed_placeholder_session(app: &AppState, session: SessionSummary) {
    app.local().seed_session(session);
}

fn resolve_buffer_view(view: ReadView) -> BufferView {
    match view {
        ReadView::Plain => BufferView::Plain,
        ReadView::Ansi => BufferView::Ansi,
        ReadView::Raw => BufferView::Raw,
    }
}

fn render_output_page(page: BufferReadPage, line_number_mode: LineNumberMode) -> PtyOutputPage {
    let text = match line_number_mode {
        LineNumberMode::None => page
            .lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        LineNumberMode::Embedded => page
            .lines
            .iter()
            .map(|line| format!("{}\t{}", line.line_number, line.text))
            .collect::<Vec<_>>()
            .join("\n"),
    };

    PtyOutputPage {
        offset: page.offset,
        returned: page.returned,
        has_more: page.has_more,
        total_lines: page.total_lines,
        text,
    }
}

#[derive(Debug, Clone, Copy)]
struct CaptureOptions {
    limit: usize,
    capture_wait_ms: u64,
    view: BufferView,
    line_number_mode: LineNumberMode,
}

fn validate_capture_options(
    capture_limit: Option<usize>,
    capture_wait_ms: Option<u64>,
    output_view: Option<ReadView>,
    line_number_mode: Option<LineNumberMode>,
) -> Result<Option<CaptureOptions>, ErrorData> {
    if capture_limit.is_none()
        && (capture_wait_ms.is_some() || output_view.is_some() || line_number_mode.is_some())
    {
        return Err(invalid_params(
            "capture_limit is required when capture_wait_ms, output_view, or line_number_mode is provided",
        ));
    }

    let Some(limit) = capture_limit else {
        return Ok(None);
    };

    let view = output_view.unwrap_or(ReadView::Plain);
    let line_number_mode = line_number_mode.unwrap_or(LineNumberMode::None);
    validate_line_number_mode(view.clone(), line_number_mode)?;

    Ok(Some(CaptureOptions {
        limit: limit.max(1),
        capture_wait_ms: capture_wait_ms.unwrap_or(0),
        view: resolve_buffer_view(view),
        line_number_mode,
    }))
}

fn validate_line_number_mode(
    output_view: ReadView,
    line_number_mode: LineNumberMode,
) -> Result<(), ErrorData> {
    if matches!(output_view, ReadView::Raw) && matches!(line_number_mode, LineNumberMode::Embedded)
    {
        return Err(invalid_params(
            "line_number_mode=embedded cannot be used with output_view=raw",
        ));
    }
    Ok(())
}

async fn capture_initial_output(
    app: &AppState,
    session_id: &SessionId,
    wait_for_output_ms: u64,
    limit: usize,
    view: BufferView,
    line_number_mode: LineNumberMode,
) -> anyhow::Result<Option<PtyOutputPage>> {
    let started = tokio::time::Instant::now();

    loop {
        let page = app.local().read_session(
            session_id,
            &BufferReadRequest {
                offset: 0,
                limit,
                pattern: None,
                ignore_case: false,
                view,
            },
        )?;

        if page.returned > 0 {
            return Ok(Some(render_output_page(page, line_number_mode)));
        }

        if started.elapsed() >= std::time::Duration::from_millis(wait_for_output_ms) {
            return Ok(None);
        }

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

fn enrich_sessions_with_ssh_context(app: &AppState) -> Vec<SessionSummary> {
    let mut sessions = app.local().list_sessions();
    let mut relation_index = std::collections::BTreeMap::<SessionId, SshConnectionSummary>::new();

    for connection in app.ssh().list_connections() {
        if let Ok(relations) = app.ssh().connection_relations(&connection.connection_id) {
            for session_id in relations.session_ids {
                relation_index.insert(session_id, connection.clone());
            }
        }
    }

    for session in &mut sessions {
        if let Some(connection) = relation_index.get(&session.session_id) {
            session.transport = SessionTransport::Ssh;
            session.connection_id = Some(connection.connection_id.clone());
            session.target_summary = Some(connection.target_summary.clone());
            if session.remote_command.is_none() {
                session.remote_command = Some("remote-session".to_string());
            }
        }
    }

    sessions
}

impl From<SshMountSummary> for SshMountSummaryView {
    fn from(value: SshMountSummary) -> Self {
        Self {
            mount_id: value.mount_id,
            title: value.title,
            description: value.description,
            connection_id: value.connection_id,
            target_summary: value.target_summary,
            status: value.status,
            backend: value.backend,
            target_path: value.local_path,
            remote_path: value.remote_path,
            read_only: value.read_only,
            mounted_at: value.mounted_at,
            last_error: value.last_error,
        }
    }
}
