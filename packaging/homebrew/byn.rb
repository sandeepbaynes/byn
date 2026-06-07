# Homebrew formula for byn — install with:
#   brew tap sandeepbaynes/tap          # once your tap repo exists
#   brew install byn
#
# This formula installs the prebuilt binary (source stays private). After
# `make dist`, host dist/byn-* at https://github.com/sandeepbaynes/byn/releases/download/v<version>/ and
# paste the SHA-256s (from dist/byn-<version>.sha256) below.
class Byn < Formula
  desc "Local-first secure secrets vault and credential manager"
  homepage "https://github.com/sandeepbaynes/byn"
  version "0.0.1"
  license "BUSL-1.1"

  on_macos do
    on_arm do
      url "https://github.com/sandeepbaynes/byn/releases/download/v0.0.1/byn-darwin-arm64"
      sha256 "REPLACE_WITH_byn-darwin-arm64_SHA256"
    end
    on_intel do
      url "https://github.com/sandeepbaynes/byn/releases/download/v0.0.1/byn-darwin-amd64"
      sha256 "REPLACE_WITH_byn-darwin-amd64_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/sandeepbaynes/byn/releases/download/v0.0.1/byn-linux-arm64"
      sha256 "REPLACE_WITH_byn-linux-arm64_SHA256"
    end
    on_intel do
      url "https://github.com/sandeepbaynes/byn/releases/download/v0.0.1/byn-linux-amd64"
      sha256 "REPLACE_WITH_byn-linux-amd64_SHA256"
    end
  end

  def install
    bin.install Dir["byn-*"].first => "byn"
  end

  test do
    assert_match "byn #{version}", shell_output("#{bin}/byn version")
  end
end
