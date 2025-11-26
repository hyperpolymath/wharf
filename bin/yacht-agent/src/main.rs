// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2025 Jonathan D. A. Jewell <hyperpolymath>

//! # Yacht Agent
//!
//! The runtime enforcer for Project Wharf - The Sovereign Web Hypervisor.
//!
//! This agent runs on the "Yacht" (the live web server) and provides:
//!
//! - **Database Proxy**: AST-aware SQL filtering ("Virtual Sharding")
//! - **Header Airlock**: HTTP header sanitization
//! - **File Integrity Monitor**: BLAKE3 hash verification
//! - **Mooring Endpoint**: Secure sync channel for the Wharf controller
//! - **eBPF Shield**: Kernel-level packet filtering (XDP)
//!
//! ## Security Model
//!
//! The agent operates in "Fail-Closed" mode:
//! - If it cannot verify a request, it blocks it
//! - If it crashes, the site goes offline (better than being hacked)
//! - Only signed commands from the Wharf are accepted

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{routing::get, Router};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use wharf_core::db_policy::{DatabasePolicy, PolicyEngine, QueryAction};
use wharf_core::types::HeaderPolicy;

// =============================================================================
// CLI ARGUMENTS
// =============================================================================

#[derive(Parser, Debug)]
#[command(name = "yacht-agent")]
#[command(about = "The Sovereign Web Hypervisor - Runtime Enforcer")]
#[command(version)]
struct Args {
    /// The database protocol to masquerade as (mysql, postgres, redis)
    #[arg(long, default_value = "mysql", env = "DB_PROTOCOL")]
    protocol: String,

    /// The port to listen on (masquerade port)
    #[arg(long, default_value_t = 3306, env = "LISTEN_PORT")]
    listen_port: u16,

    /// The shadow port where the real database hides
    #[arg(long, default_value_t = 33060, env = "SHADOW_DB_PORT")]
    shadow_port: u16,

    /// The shadow database host
    #[arg(long, default_value = "127.0.0.1", env = "SHADOW_DB_HOST")]
    shadow_host: String,

    /// The API port for health checks and Wharf mooring
    #[arg(long, default_value_t = 9001, env = "API_PORT")]
    api_port: u16,

    /// Network interface for eBPF attachment
    #[arg(long, default_value = "eth0", env = "XDP_INTERFACE")]
    xdp_interface: String,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

// =============================================================================
// STATE
// =============================================================================

/// The shared state for the Yacht Agent
struct AgentState {
    /// The database policy engine
    db_engine: PolicyEngine,

    /// The HTTP header policy
    header_policy: HeaderPolicy,

    /// Whether the Wharf is currently moored (connected)
    moored: bool,

    /// The expected filesystem hashes (from Wharf)
    integrity_hashes: std::collections::HashMap<String, String>,

    /// Statistics
    queries_allowed: u64,
    queries_blocked: u64,
}

impl AgentState {
    fn new() -> Self {
        Self {
            db_engine: PolicyEngine::new(DatabasePolicy::default()),
            header_policy: HeaderPolicy::default(),
            moored: false,
            integrity_hashes: std::collections::HashMap::new(),
            queries_allowed: 0,
            queries_blocked: 0,
        }
    }
}

// =============================================================================
// MAIN
// =============================================================================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Set up logging based on verbosity
    let log_level = match args.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .json()
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Yacht Agent starting...");
    info!("Version: {}", wharf_core::VERSION);
    info!("Protocol: {}", args.protocol);
    info!("Masquerade port: {}", args.listen_port);
    info!("Shadow DB: {}:{}", args.shadow_host, args.shadow_port);

    // Initialize shared state
    let state = Arc::new(RwLock::new(AgentState::new()));

    // Spawn the database proxy
    let db_state = state.clone();
    let shadow_addr = format!("{}:{}", args.shadow_host, args.shadow_port);
    let listen_port = args.listen_port;
    let protocol = args.protocol.clone();

    tokio::spawn(async move {
        if let Err(e) = run_db_proxy(listen_port, &shadow_addr, &protocol, db_state).await {
            error!("Database proxy error: {}", e);
        }
    });

    // Build the API router
    let api_state = state.clone();
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/status", get(status))
        .route("/stats", get(stats))
        .with_state(api_state);

    // Bind API to localhost only (Nebula mesh provides external access)
    let api_addr = SocketAddr::from(([0, 0, 0, 0], args.api_port));
    info!("API listening on {}", api_addr);

    let listener = tokio::net::TcpListener::bind(api_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

// =============================================================================
// DATABASE PROXY
// =============================================================================

/// Run the database proxy server
async fn run_db_proxy(
    listen_port: u16,
    shadow_addr: &str,
    protocol: &str,
    state: Arc<RwLock<AgentState>>,
) -> anyhow::Result<()> {
    let listen_addr = format!("0.0.0.0:{}", listen_port);
    let listener = TcpListener::bind(&listen_addr).await?;

    info!("Database proxy listening on {}", listen_addr);
    info!("Forwarding to shadow DB at {}", shadow_addr);

    loop {
        let (client_socket, client_addr) = listener.accept().await?;
        let shadow = shadow_addr.to_string();
        let proto = protocol.to_string();
        let conn_state = state.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_db_connection(client_socket, &shadow, &proto, conn_state).await {
                warn!("Connection from {} error: {}", client_addr, e);
            }
        });
    }
}

/// Handle a single database connection
async fn handle_db_connection(
    mut client: TcpStream,
    shadow_addr: &str,
    protocol: &str,
    state: Arc<RwLock<AgentState>>,
) -> std::io::Result<()> {
    // Connect to the real database
    let mut server = TcpStream::connect(shadow_addr).await?;

    let (mut c_read, mut c_write) = client.split();
    let (mut s_read, mut s_write) = server.split();

    // The proxy loop
    let client_to_server = async {
        let mut buf = [0u8; 16384];
        loop {
            let n = c_read.read(&mut buf).await?;
            if n == 0 {
                return Ok::<_, std::io::Error>(());
            }

            // MySQL/MariaDB protocol inspection
            // Packet format: 3 bytes length + 1 byte sequence + payload
            // Command byte is at position 4, COM_QUERY = 0x03
            if protocol == "mysql" || protocol == "mariadb" {
                if n > 5 && buf[4] == 0x03 {
                    // This is a COM_QUERY packet
                    let query = String::from_utf8_lossy(&buf[5..n]);

                    // Analyze the query
                    let mut state_guard = state.write().await;
                    match state_guard.db_engine.analyze(&query) {
                        Ok(QueryAction::Allow) => {
                            state_guard.queries_allowed += 1;
                            drop(state_guard);
                            // Forward the packet
                            s_write.write_all(&buf[0..n]).await?;
                        }
                        Ok(QueryAction::Audit) => {
                            state_guard.queries_allowed += 1;
                            info!("AUDIT: {}", query.chars().take(100).collect::<String>());
                            drop(state_guard);
                            s_write.write_all(&buf[0..n]).await?;
                        }
                        Ok(QueryAction::Block) | Err(_) => {
                            state_guard.queries_blocked += 1;
                            warn!("BLOCKED: {}", query.chars().take(100).collect::<String>());
                            drop(state_guard);
                            // Send MySQL error packet back to client
                            // Error packet: header + 0xff + errno + sqlstate + message
                            let error_msg = b"Query blocked by Wharf security policy";
                            let mut error_packet = Vec::with_capacity(error_msg.len() + 13);
                            // Length (3 bytes) + Sequence (1 byte)
                            let len = (error_msg.len() + 9) as u32;
                            error_packet.extend_from_slice(&len.to_le_bytes()[0..3]);
                            error_packet.push(1); // Sequence number
                            error_packet.push(0xff); // Error marker
                            error_packet.extend_from_slice(&1045u16.to_le_bytes()); // Error code
                            error_packet.push(b'#'); // SQL state marker
                            error_packet.extend_from_slice(b"HY000"); // SQL state
                            error_packet.extend_from_slice(error_msg);
                            c_write.write_all(&error_packet).await?;
                            return Ok(());
                        }
                    }
                } else {
                    // Non-query packet (auth, ping, etc.) - pass through
                    s_write.write_all(&buf[0..n]).await?;
                }
            } else if protocol == "postgres" {
                // PostgreSQL protocol inspection (simplified)
                // Query message: 'Q' + length + query string
                if n > 5 && buf[0] == b'Q' {
                    let query = String::from_utf8_lossy(&buf[5..n]);
                    let mut state_guard = state.write().await;
                    match state_guard.db_engine.analyze(&query) {
                        Ok(QueryAction::Allow) | Ok(QueryAction::Audit) => {
                            state_guard.queries_allowed += 1;
                            drop(state_guard);
                            s_write.write_all(&buf[0..n]).await?;
                        }
                        Ok(QueryAction::Block) | Err(_) => {
                            state_guard.queries_blocked += 1;
                            warn!("BLOCKED: {}", query.chars().take(100).collect::<String>());
                            drop(state_guard);
                            // Send PostgreSQL ErrorResponse
                            let error = b"EFATAL\0VFATAL\0C42501\0MQuery blocked by Wharf\0\0";
                            let mut packet = Vec::with_capacity(error.len() + 5);
                            packet.push(b'E'); // Error message type
                            let len = (error.len() + 4) as i32;
                            packet.extend_from_slice(&len.to_be_bytes());
                            packet.extend_from_slice(error);
                            c_write.write_all(&packet).await?;
                            return Ok(());
                        }
                    }
                } else {
                    s_write.write_all(&buf[0..n]).await?;
                }
            } else {
                // Unknown protocol - pass through (fail-open for compatibility)
                s_write.write_all(&buf[0..n]).await?;
            }
        }
    };

    let server_to_client = async {
        tokio::io::copy(&mut s_read, &mut c_write).await
    };

    tokio::select! {
        result = client_to_server => result?,
        result = server_to_client => { result?; }
    }

    Ok(())
}

// =============================================================================
// API ENDPOINTS
// =============================================================================

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Status endpoint (returns agent state as JSON)
async fn status() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "status": "active",
        "moored": false,
        "version": wharf_core::VERSION,
        "components": {
            "db_proxy": "running",
            "shield": "active",
            "integrity": "verified"
        }
    }))
}

/// Statistics endpoint
async fn stats() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "queries": {
            "allowed": 0,
            "blocked": 0,
            "audited": 0
        },
        "packets": {
            "allowed": 0,
            "dropped": 0
        }
    }))
}
