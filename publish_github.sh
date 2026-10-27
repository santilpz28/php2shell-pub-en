#!/bin/bash
# Publishes the PHP2Shell lab at github.com/santilpz28/php2shell-pub-en
#
# Prerequisite: the repo MUST exist (empty) on GitHub. GitHub does not allow
# creating repositories via push over SSH, and this machine has no PAT
# with API permissions stored.
#
#   https://github.com/new?name=php2shell-pub-en
#
# Usage:  bash publish_github.sh
set -euo pipefail

REPO="git@github.com:santilpz28/php2shell-pub-en.git"
STAGE="/tmp/php2shell-pub-en"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Publishing PHP2Shell → $REPO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -d "$STAGE/.git" ]; then
    echo "❌ Staging does not exist at $STAGE"
    exit 1
fi

cd "$STAGE"

echo "→ Verifying that the remote repo exists..."
if ! git ls-remote "$REPO" >/dev/null 2>&1; then
    echo "❌ The remote repo does not exist or is not accessible."
    echo "   Create it here: https://github.com/new?name=php2shell-pub-en"
    echo "   (without initializing README, .gitignore or license)"
    exit 1
fi

echo "→ Push..."
git push -u origin main --force

echo "→ Verifying via public API..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" "https://api.github.com/repos/santilpz28/php2shell-lab")
echo "  https://github.com/santilpz28/php2shell-lab → HTTP $HTTP"
echo
echo "✅ Published. Don't forget to set the description and the topics on GitHub:"
echo "   topics: php, security, cve, rce, use-after-free, vulnerability-research"
