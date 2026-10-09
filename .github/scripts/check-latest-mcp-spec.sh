#!/usr/bin/env bash
set -euo pipefail

# The PR gate is intentionally strict: a published revision requires a schema
# update and a product behavior review before any PR can pass.
manifest=schema/versions.json
known=$(jq -r '.versions | max' "$manifest")
if [[ ! "$known" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo '::error::schema/versions.json has no dated MCP revision' >&2
  exit 1
fi
upstream=$(gh api repos/modelcontextprotocol/modelcontextprotocol/contents/schema \
  --jq '.[] | select(.type == "dir") | .name' |
  grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' | sort | tail -n 1)
if [[ -z "$upstream" ]]; then
  echo '::error::Could not find a published MCP schema revision upstream' >&2
  exit 1
fi
if [[ "$known" != "$upstream" ]]; then
  echo "::error::Latest published MCP schema is $upstream; vendored latest is $known. Vendor it and assess the implemented surface before merging." >&2
  exit 1
fi
if [[ ! -s "schema/$known/schema.json" ]]; then
  echo "::error::schema/$known/schema.json is missing" >&2
  exit 1
fi
echo "Product gate uses the latest published MCP schema: $known"
