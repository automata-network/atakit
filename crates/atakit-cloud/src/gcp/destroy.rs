//! GCP destroy helpers.
//!
//! Destroy logic is implemented directly in `GcpProvider::plan_destroy` and
//! `GcpProvider::execute_destroy_step`. Individual resource deletion functions
//! live in their respective modules (instance, disk, firewall, image).
