# typed: strict
# frozen_string_literal: true

# Homebrew formula for the ARC sidecar binary.
#
# Tap setup (one-time):
#   brew tap backbay/arc https://github.com/backbay/arc
#   brew install backbay/arc/arc
#
# SHA-256 placeholders below are rewritten by the release-binaries workflow
# before the formula is published to the tap.
class Arc < Formula
  desc "Provable Agent Capability Transport sidecar runtime"
  homepage "https://github.com/backbay/arc"
  version "0.1.0"
  license "Apache-2.0"

  # Pre-built binaries published by .github/workflows/release-binaries.yml.
  # The URLs resolve to the GitHub Release assets for the matching tag.
  on_macos do
    on_arm do
      url "https://github.com/backbay/arc/releases/download/v#{version}/arc-#{version}-aarch64-apple-darwin.tar.gz"
      sha256 "1111111111111111111111111111111111111111111111111111111111111111"
    end
    on_intel do
      url "https://github.com/backbay/arc/releases/download/v#{version}/arc-#{version}-x86_64-apple-darwin.tar.gz"
      sha256 "2222222222222222222222222222222222222222222222222222222222222222"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/backbay/arc/releases/download/v#{version}/arc-#{version}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "3333333333333333333333333333333333333333333333333333333333333333"
    end
    on_intel do
      url "https://github.com/backbay/arc/releases/download/v#{version}/arc-#{version}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "4444444444444444444444444444444444444444444444444444444444444444"
    end
  end

  def install
    bin.install "arc"
  end

  test do
    # Smoke test: the binary must at least report its version.
    assert_match(/arc/i, shell_output("#{bin}/arc --version"))
  end
end
