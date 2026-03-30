# Phase 63: Portable Status, Revocation, and Type Metadata - Context

## Goal

Project ARC passport lifecycle truth into portable verifier-facing status,
revocation, supersession, and type-metadata surfaces without inventing a new
trust root.

## Why This Phase Exists

Standards-native issuance is incomplete if verifiers cannot validate the
credential type, issuer, and current lifecycle state through stable metadata
and status artifacts.

## Scope

- issuer metadata and type metadata
- portable status and revocation publication
- supersession and cache-boundary semantics

## Out of Scope

- OID4VP wallet transport
- public wallet discovery networks
- mutable lifecycle truth outside ARC operator control
