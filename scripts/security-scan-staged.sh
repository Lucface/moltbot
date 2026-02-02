#!/bin/sh
# Security scanner for staged files.
# Called by git-hooks/pre-commit.
# Patterns are split across variables to avoid self-detection by hooks.

ROOT="$1"
[ -z "$ROOT" ] && exit 0

STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(ts|tsx|js|jsx|html|svelte)$')
[ -z "$STAGED" ] && exit 0

ERRORS=0
IH="inner""HTML"
EV="ev""al"
NF="new Fun""ction"
DS="dangerous""lySetInner""HTML"

for FILE in $STAGED; do
  case "$FILE" in
    *.test.ts|*.test.tsx|*.e2e.test.*|*/a2ui.bundle.js|*/security-scan*) continue ;;
  esac
  CONTENT=$(git show ":$FILE" 2>/dev/null) || continue

  # 1. Dynamic innerHTML assignment
  if printf '%s' "$CONTENT" | grep -qE "\.${IH}\s*=\s*[^\"'\`]"; then
    echo "SEC: $FILE — dynamic $IH assignment. Use textContent or DOMPurify."
    ERRORS=$((ERRORS + 1))
  fi

  # 2. eval() usage
  if printf '%s' "$CONTENT" | grep -qE "\\b${EV}\s*\("; then
    echo "SEC: $FILE — $EV() detected. Use safer alternatives."
    ERRORS=$((ERRORS + 1))
  fi

  # 3. Function constructor
  if printf '%s' "$CONTENT" | grep -qE "${NF}\s*\("; then
    echo "SEC: $FILE — $NF() detected. Use safer alternatives."
    ERRORS=$((ERRORS + 1))
  fi

  # 4. React dangerouslySetInnerHTML
  if printf '%s' "$CONTENT" | grep -qE "$DS"; then
    echo "SEC: $FILE — $DS found. Ensure DOMPurify sanitization."
    ERRORS=$((ERRORS + 1))
  fi

  # 5. Hardcoded secrets
  if printf '%s' "$CONTENT" | grep -qE '(sk-[a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[a-zA-Z0-9]{36})'; then
    echo "SEC: $FILE — possible hardcoded secret. Use env vars."
    ERRORS=$((ERRORS + 1))
  fi

  # 6. SQL injection via string concatenation
  if printf '%s' "$CONTENT" | grep -qE '(SELECT|INSERT|UPDATE|DELETE|DROP).*\+\s*(req\.|params\.|body\.|query\.)'; then
    echo "SEC: $FILE — possible SQL injection. Use parameterized queries."
    ERRORS=$((ERRORS + 1))
  fi

  # 7. Shell injection via exec with template literal
  if printf '%s' "$CONTENT" | grep -qE 'exec\(\s*`' | grep -vqE 'execFile'; then
    echo "SEC: $FILE — shell command with template literal. Use execFile + args."
    ERRORS=$((ERRORS + 1))
  fi
done

if [ "$ERRORS" -gt 0 ]; then
  echo ""
  echo "Blocked $ERRORS security issue(s). Fix them or --no-verify to bypass."
  exit 1
fi
