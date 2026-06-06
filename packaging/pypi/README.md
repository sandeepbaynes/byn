# byn (name reservation)

This PyPI distribution reserves the name **`byn`**. byn is a **Go CLI** — a
local-first secure secrets vault and credential manager — not a Python
package. It installs no `byn` command, so it can't shadow the real binary.

## Install the real byn

```sh
go install github.com/sandeepbaynes/byn/cmd/byn@latest
brew install sandeepbaynes/tap/byn
curl -fsSL https://raw.githubusercontent.com/sandeepbaynes/byn/main/install.sh | sh
```

Homepage: https://github.com/sandeepbaynes/byn · © 2026 Sandeep Baynes · PolyForm Noncommercial 1.0.0
