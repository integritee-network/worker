#!/usr/bin/env bash

# original file taken from https://github.com/paritytech/substrate
# License: Apache II

# shellcheck source=shellcheck.sh
source "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )/shellcheck.sh"

version="$2"
last_version="$1"

all_changes="$(sanitised_git_logs "$last_version" "$version")"
core_changes=""
client_changes=""
applibs_changes=""
sidechain_changes=""
offchain_changes=""
teeracle_changes=""
evm_changes=""
somethingelse_changes=""
changes=""
migrations=""


# Checks whether a given PR has a given label.
# repo: 'organization/repo'
# pr_id: 12345
# label: B1-silent
# Usage: has_label $repo $pr_id $label
has_label(){
  repo="$1"
  pr_id="$2"
  label="$3"

  # These will exist if the function is called in Gitlab.
  # If the function's called in Github, we should have GITHUB_ACCESS_TOKEN set
  # already.
  if [ -n "$GITHUB_RELEASE_TOKEN" ]; then
    GITHUB_TOKEN="$GITHUB_RELEASE_TOKEN"
  elif [ -n "$GITHUB_PR_TOKEN" ]; then
    GITHUB_TOKEN="$GITHUB_PR_TOKEN"
  fi

  out=$(curl -H "Authorization: token $GITHUB_TOKEN" -s "$api_base/$repo/pulls/$pr_id")
  [ -n "$(echo "$out" | tr -d '\r\n' | jq ".labels | .[] | select(.name==\"$label\")")" ]
}

while IFS= read -r line; do
  pr_id=$(echo "$line" | sed -E 's/.*#([0-9]+)\)$/\1/')

  # Skip if the PR has the silent label - this allows us to skip a few requests
  if has_label 'integritee-network/worker' "$pr_id" 'B0-silent'; then
    continue
  fi
  if has_label 'pintegritee-network/worker' "$pr_id" 'B1-releasenotes' ; then
    if has_label 'pintegritee-network/worker' "$pr_id" 'A0-core' ; then
      core_changes="$core_changes
  $line"
    fi
    if has_label 'pintegritee-network/worker' "$pr_id" 'A1-client' ; then
      client_changes="$client_changes
  $line"
    fi
    if has_label 'pintegritee-network/worker' "$pr_id" 'A2-applibs' ; then
      applibs_changes="$applibs_changes
  $line"
    fi
    if has_label 'pintegritee-network/worker' "$pr_id" 'A3-sidechain' ; then
      sidechain_changes="$sidechain_changes
  $line"
    fi
    if has_label 'pintegritee-network/worker' "$pr_id" 'A4-offchain' ; then
      offchain_changes="$offchain_changes
  $line"
    fi
    if has_label 'pintegritee-network/worker' "$pr_id" 'A5-teeracle' ; then
      teeracle_changes="$teeracle_changes
  $line"
    fi
    if has_label 'pintegritee-network/worker' "$pr_id" 'A6-evm' ; then
      evm_changes="$evm_changes
  $line"
    fi
    if has_label 'pintegritee-network/worker' "$pr_id" 'A7-somethingelse' ; then
      somethingelse_changes="$somethingelse_changes
  $line"
    fi
  fi
done <<< "$all_changes"

# Make the substrate section if there are any substrate changes
if [ -n "$runtime_changes" ] ||
   [ -n "$release_changes" ] ||
   [ -n "$client_changes" ] ||
   [ -n "$migrations" ]; then
  changes=$(cat << EOF
Substrate changes
-----------------
EOF
)
  if [ -n "$runtime_changes" ]; then
    changes="$changes
Runtime
-------
$runtime_changes"
  fi
  if [ -n "$client_changes" ]; then
    changes="$changes
Client
------
$client_changes"
  fi
  if [ -n "$api_changes" ]; then
    changes="$changes
API
---
$api_changes"
  fi
  release_text="$release_text
$changes"
fi
if [ -n "$migrations" ]; then
  changes="$changes
Runtime Migrations
------------------
$migrations"
fi

echo "$changes"
