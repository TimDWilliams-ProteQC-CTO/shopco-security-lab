#!/usr/bin/env bash
# =============================================================================
# beef_install.sh
# BeEF (Browser Exploitation Framework) Installation Script
# BBC Academy / JBI Training  |  Secure Web Application Development
# =============================================================================
#
# PURPOSE:
#   Automates the installation of BeEF on Ubuntu 20.04 LTS lab VMs.
#   Handles Ruby version management via rbenv and all gem dependencies.
#
# USAGE:
#   chmod +x beef_install.sh
#   ./beef_install.sh
#
# AFTER INSTALL:
#   cd ~/beef
#   ./beef
#   # Web UI: http://127.0.0.1:3000/ui/panel
#   # Default credentials: beef / beef  (change on first login)
#
# NOTE:
#   This script is intended for use in isolated training lab VMs only.
#   Do NOT run on production systems or without explicit authorisation.
# =============================================================================

set -euo pipefail

RUBY_VERSION="3.1.4"
BEEF_DIR="$HOME/beef"

echo "============================================="
echo " BeEF Installation Script"
echo " JBI Training / BBC Academy Lab Setup"
echo "============================================="

# ── Step 1: System dependencies ──────────────────────────────────────────────
echo "[1/6] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y \
    git curl libssl-dev libreadline-dev zlib1g-dev \
    autoconf bison build-essential libyaml-dev \
    libreadline-dev libncurses5-dev libffi-dev libgdbm-dev \
    nodejs npm

# ── Step 2: rbenv ─────────────────────────────────────────────────────────────
echo "[2/6] Installing rbenv..."
if [ ! -d "$HOME/.rbenv" ]; then
    git clone https://github.com/rbenv/rbenv.git ~/.rbenv
    echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
    echo 'eval "$(rbenv init -)"' >> ~/.bashrc
fi

if [ ! -d "$HOME/.rbenv/plugins/ruby-build" ]; then
    git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build
fi

export PATH="$HOME/.rbenv/bin:$PATH"
eval "$(rbenv init -)"

# ── Step 3: Ruby ──────────────────────────────────────────────────────────────
echo "[3/6] Installing Ruby $RUBY_VERSION (this may take 5-10 minutes)..."
if ! rbenv versions | grep -q "$RUBY_VERSION"; then
    rbenv install "$RUBY_VERSION"
fi
rbenv global "$RUBY_VERSION"
ruby --version

# ── Step 4: Bundler ───────────────────────────────────────────────────────────
echo "[4/6] Installing Bundler..."
gem install bundler --no-document

# ── Step 5: Clone BeEF ────────────────────────────────────────────────────────
echo "[5/6] Cloning BeEF repository..."
if [ ! -d "$BEEF_DIR" ]; then
    git clone https://github.com/beefproject/beef.git "$BEEF_DIR"
fi

# ── Step 6: Install BeEF gems ─────────────────────────────────────────────────
echo "[6/6] Installing BeEF gem dependencies..."
cd "$BEEF_DIR"
bundle install --without test development

echo ""
echo "============================================="
echo " Installation complete!"
echo "============================================="
echo ""
echo " To start BeEF:"
echo "   cd ~/beef && ./beef"
echo ""
echo " Web UI:  http://127.0.0.1:3000/ui/panel"
echo " Hook URL to inject into pages:"
echo "   http://<VM-IP>:3000/hook.js"
echo ""
echo " REMINDER: Use only in the lab environment"
echo "           with explicit instructor authorisation."
echo "============================================="
