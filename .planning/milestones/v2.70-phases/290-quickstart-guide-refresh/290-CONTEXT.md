# Phase 290 Context

## Goal

Refresh the repo README so a developer can reach an ARC-governed tool call in
under five minutes and discover the new framework examples easily.

## Implementation Direction

- Refresh `README.md` around the published GHCR images:
  `ghcr.io/bb-connor/arc:main` and `ghcr.io/bb-connor/arc-mcp-demo:main`.
- Keep local build fallback in the Docker example docs and Compose file.
- Add a framework-examples section pointing to the new Anthropic SDK,
  LangChain, and Docker example directories.
