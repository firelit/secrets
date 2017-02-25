# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)

Gem::Specification.new do |gem|
  gem.name          = 'team-secrets'
  gem.version       = '0.1.0'
  gem.platform      = Gem::Platform::RUBY
  gem.authors       = ['Eric Bigoness']
  gem.email         = ['design@firelit.com']
  gem.homepage      = 'https://github.com/firelit/secrets'

  gem.summary       = 'A utility for securely managing team secrets'
  gem.description   = 'Encyrpt and store team secrets, passwords and API keys in a repository with built-in user management'

  gem.files         = `git ls-files`.split("\n")
  gem.executables   = ['team-secrets']
  gem.test_files    = `git ls-files -- {test,spec,features}/*.rb`.split("\n")
  gem.require_paths = ["lib"]

end