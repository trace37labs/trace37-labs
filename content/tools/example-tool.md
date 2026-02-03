---
title: "ExampleScanner"
date: 2026-02-03
draft: true
description: "Example tool template"
tags: ["scanner", "python"]
github: "https://github.com/trace37labs/example-scanner"
---

A fast and lightweight security scanner for identifying common misconfigurations.

## Features

- Fast concurrent scanning
- JSON/CSV output formats
- Extensible plugin system
- CI/CD integration ready

## Installation

```bash
pip install example-scanner
```

## Usage

```bash
# Basic scan
example-scanner target.com

# Full scan with output
example-scanner -o results.json --full target.com
```

## Configuration

Create a `config.yaml` file:

```yaml
threads: 10
timeout: 30
output_format: json
```
