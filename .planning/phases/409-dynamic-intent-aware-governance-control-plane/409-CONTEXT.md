---
phase: 409
milestone: v3.16
title: Dynamic Intent-Aware Governance Control Plane
status: complete locally 2026-04-15
created: 2026-04-15
---

# Phase 409 Context

## Goal

Lift route choice from static bridge metadata into a dynamic intent-aware
governance control plane.

## Why This Exists

The original vision is stronger than a registry-backed executor fabric. It
requires a control plane that can choose, attenuate, or deny routes based on
intent, capability, policy, and runtime state.

## Must Become True

- governed intent is a first-class input to route planning
- ARC can select, attenuate, or deny candidate routes dynamically
- route-selection evidence is signed and visible on claim-eligible surfaces
