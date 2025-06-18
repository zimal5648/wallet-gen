# Octra Wallet Generator (TypeScript Version)

A secure wallet generator for Octra blockchain written in TypeScript using Bun's native server.

## Features

- **BIP39 Mnemonic Generation**: Creates 12-word mnemonic phrases
- **Ed25519 Cryptography**: Uses TweetNaCl for secure key generation
- **HD Key Derivation**: Hierarchical deterministic wallet support
- **Octra Address Format**: Creates addresses with "oct" prefix and Base58 encoding
- **Web Interface**: Modern, responsive web UI
- **Real-time Generation**: Streaming updates during wallet creation
- **Auto-save**: Automatically saves generated wallets to disk
- **Cross-platform Executables**: Pre-built binaries for Linux, Windows, and macOS (x64 & ARM)

## Installation

### Option 1: Download Pre-built Executable (Recommended)

1. **Download the latest release:**
   - Go to the [Releases page](../../releases)
   - Download the appropriate binary for your platform:
     - `wallet-generator-linux-x64.tar.gz` for Linux x64
     - `wallet-generator-windows-x64.zip` for Windows x64
     - `wallet-generator-macos-x64.tar.gz` for macOS Intel
     - `wallet-generator-macos-arm64.tar.gz` for macOS Apple Silicon

2. **Extract and run:**
   
   **Linux/macOS:**
   ```bash
   tar -xzf wallet-generator-*.tar.gz
   chmod +x wallet-generator
   # On macOS, you may need to remove quarantine flag to run unsigned binary:
   xattr -r -d com.apple.quarantine wallet-generator
   ./wallet-generator
   ```
   
   **Windows:**
   ```bash
   # Extract the .zip file
   .\wallet-generator.exe
   ```

3. **Open your browser:**
   Navigate to `http://localhost:8888`

### Option 2: Build from Source

1. **Install Bun (if not already installed):**
   
   **macOS and Linux:**
   ```bash
   curl -fsSL https://bun.sh/install | bash
   ```
   
   **Windows:**
   ```bash
   powershell -c "irm bun.sh/install.ps1 | iex"
   ```
   
   **Alternative methods:**
   - **Homebrew (macOS):** `brew install bun`
   - **Scoop (Windows):** `scoop install bun`
   - **npm:** `npm install -g bun`
   
   Verify installation: `bun --version`

2. **Clone and install dependencies:**
   ```bash
   git clone <repository-url>
   cd wallet-gen
   bun install
   ```

3. **Build standalone executable (optional):**
   ```bash
   bun run build
   ```

## Usage

### Running from Executable

If you downloaded a pre-built executable, simply run it and navigate to `http://localhost:8888`.

### Running from Source

1. **Start the server:**
   ```bash
   bun start
   # or
   bun wallet_generator.ts
   ```

2. **For development with auto-reload:**
   ```bash
   bun dev
   ```

3. **Open your browser:**
   Navigate to `http://localhost:8888`

### Generating Wallets

1. **Generate a wallet:**
   Click "GENERATE NEW WALLET" and watch the real-time progress

2. **Wallet features:**
   - View mnemonic phrase, private/public keys, and address
   - Test signature functionality
   - Derive addresses for different network types
   - Auto-save wallet file to disk

## Dependencies

- **tweetnacl**: Ed25519 cryptography
- **bip39**: BIP39 mnemonic generation and validation
- Uses Bun's built-in crypto module and HTTP server (no Express needed)
- Uses Bun's native file serving and streaming capabilities

## Build & Release

### Building Locally

To build a standalone executable for your current platform:

```bash
bun run build
```

This creates a `wallet-generator` executable (or `wallet-generator.exe` on Windows) that includes all dependencies and static assets (HTML, fonts, and images).

## Security Warning

⚠️ **IMPORTANT**: This tool generates real cryptographic keys. Always:
- Keep your private keys secure
- Never share your mnemonic phrase
- Don't store wallet files on cloud services
- Use this on a secure, offline computer for production wallets

## Technical Details

- **Runtime**: Bun (fast JavaScript/TypeScript runtime)
- **Entropy**: 128-bit cryptographically secure random generation
- **Key Derivation**: Custom HD path: `m/345'/cointype'/network'/contract'/account'/token'/subnet'/index`
- **Address Format**: `oct` + Base58(SHA256(publickey))
- **Signature Algorithm**: Ed25519
- **Seed Derivation**: PBKDF2-HMAC-SHA512 with 2048 iterations

## Differences from Python Version

The TypeScript version maintains full compatibility with the Python version's wallet format and cryptographic operations, but uses different libraries:

- `tweetnacl` instead of `nacl.signing`
- `bip39` library instead of manual BIP39 implementation
- Bun's native HTTP server instead of Flask
- Bun's built-in `crypto` instead of Python's `hashlib` and `secrets`

## Performance

This version runs on Bun with native HTTP server, which provides:
- Faster startup times compared to Node.js
- Built-in bundler and transpiler  
- Native TypeScript support
- Better performance for HTTP servers (no Express overhead)
- Optimized streaming for real-time wallet generation
- Zero-copy file serving for static assets

## Port

The server runs on port 8888 by default. You can modify this in the `wallet_generator.ts` file if needed.
