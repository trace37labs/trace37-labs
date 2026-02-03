# Trace37 Labs

Offensive security research site built with Hugo.

## Local Development

```bash
# Install Hugo (https://gohugo.io/installation/)
# macOS
brew install hugo

# Run locally
hugo server -D
```

Visit http://localhost:1313

## Creating Content

```bash
# New blog post
hugo new blog/my-post.md

# New CVE writeup
hugo new cves/cve-2026-xxxxx.md

# New tool
hugo new tools/my-tool.md
```

## Deployment

Site auto-deploys to GitHub Pages on push to `main`.

