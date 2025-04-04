#!/usr/bin/env bash

# Strict mode
set -euo pipefail

# Build info
export BUILD_DATE="2025-04-04 04:54:50"
export BUILD_USER="AnmiTaliDev"

# Cake configuration
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CAKE_VERSION="3.0.0"
DOTNET_VERSION="7.0"

# Check for dotnet SDK
if ! command -v dotnet &> /dev/null; then
    echo "Installing .NET SDK ${DOTNET_VERSION}..."
    curl -sSL https://dot.net/v1/dotnet-install.sh | bash /dev/stdin --version ${DOTNET_VERSION}
    export PATH="$HOME/.dotnet:$PATH"
fi

# Install Cake.Tool if not present
if ! dotnet tool list -g | grep "cake.tool" &> /dev/null; then
    dotnet tool install --global Cake.Tool --version ${CAKE_VERSION}
fi

# Run Cake script
exec dotnet cake "${SCRIPT_DIR}/build.cake" "$@"