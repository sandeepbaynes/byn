# Reservation gem for the name `byn` on RubyGems. It declares NO executables,
# so `gem install byn` can never shadow the real Go binary.
# Publish:  gem build byn.gemspec && gem push byn-0.3.0.gem
Gem::Specification.new do |s|
  s.name        = "byn"
  s.version     = "0.3.0"
  s.summary     = "Name reserved for byn — a local-first secure secrets vault & credential manager (a Go CLI)."
  s.description = "byn is a local-first secure secrets vault. This gem reserves the name; install the real CLI via `go install github.com/sandeepbaynes/byn/cmd/byn@latest`, Homebrew, or https://github.com/sandeepbaynes/byn. It installs no executable."
  s.authors     = ["Sandeep Baynes"]
  s.homepage    = "https://github.com/sandeepbaynes/byn"
  s.license     = "Nonstandard" # BUSL-1.1 (source-available) — see https://github.com/sandeepbaynes/byn
  s.files       = ["README.md"]
  s.metadata    = { "homepage_uri" => "https://github.com/sandeepbaynes/byn" }
  s.required_ruby_version = ">= 2.6"
end
