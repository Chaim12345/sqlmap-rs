//! HTTP request engine and page-comparison logic.
//! Port of sqlmap `lib/request/*` (connect, redirect handling subset) and
//! `lib/core/comparison.py` (page similarity ratio).

pub mod client;
pub mod crawl;
pub mod forms;
pub mod comparison;
pub mod params;

pub use client::{Client, RequestSpec, Response};
