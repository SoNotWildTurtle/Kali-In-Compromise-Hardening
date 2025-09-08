#!/bin/bash
# secure_dev_env.sh - install secure development environment
set -euo pipefail

apt-get update
apt-get install -y \
    code-oss \
    git \
    pre-commit \
    shellcheck \
    flake8 \
    bandit \
    black \
    codespell \
    gitleaks \
    python3-isort \
    gpg

# Configure basic git settings for security
git config --system init.defaultBranch main
git config --system log.showSignature true
git config --system commit.gpgsign true
git config --system gpg.format openpgp

# Automatically generate a GPG key for commit signing if one does not exist
if ! gpg --list-secret-keys "kaliuser@local" >/dev/null 2>&1; then
    cat <<'EOF' > /tmp/gpg_batch
    %no-protection
    Key-Type: default
    Key-Length: 2048
    Subkey-Type: default
    Name-Real: Kali Dev
    Name-Email: kaliuser@local
    Expire-Date: 0
EOF
    gpg --batch --generate-key /tmp/gpg_batch
    rm /tmp/gpg_batch
fi

KEY_ID=$(gpg --list-secret-keys --with-colons kaliuser@local | awk -F: '/^sec/{print $5; exit}')
git config --system user.signingkey "$KEY_ID"

cat <<'GIT' > /etc/gitignore_global
*.swp
*.pyc
__pycache__/
GIT

git config --system core.excludesfile /etc/gitignore_global

# Configure pre-commit for all new repositories
pre-commit init-templatedir /usr/local/share/git-templates
git config --system init.templateDir /usr/local/share/git-templates

cat <<'PC' > /etc/pre-commit-config.yaml
repos:
  - repo: https://github.com/psf/black
    rev: 24.3.0
    hooks:
      - id: black
  - repo: https://github.com/PyCQA/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.8
    hooks:
      - id: bandit
  - repo: https://github.com/koalaman/shellcheck-precommit
    rev: v0.8.0
    hooks:
      - id: shellcheck
        files: '\.sh$'
  - repo: https://github.com/PyCQA/isort
    rev: 5.13.2
    hooks:
      - id: isort
  - repo: https://github.com/codespell-project/codespell
    rev: v2.2.6
    hooks:
      - id: codespell
        args: ['-q', '2']
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.1
    hooks:
      - id: gitleaks
PC

echo "Secure coding environment installed."
