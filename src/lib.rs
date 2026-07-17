#![forbid(unsafe_code)]
//! toolcage: a per-tool-call WASM sandbox for MCP servers.
//!
//! toolcage speaks MCP over stdio to the client and runs the wrapped MCP
//! server (a wasm32-wasip1 command module) inside wasmtime. Every single
//! tools/call gets a fresh instance with only the filesystem, env, and
//! budgets that tool's policy grants. Network does not exist for the guest.

pub mod audit;
pub mod policy;
pub mod rpc;
pub mod runner;
pub mod sandbox;
pub mod server;
