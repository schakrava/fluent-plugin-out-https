# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
  gem.name          = "fluent-plugin-out-bhttps"
  gem.version       = "0.1.1"
  gem.authors       = ["Suman Chakravartula"]
  gem.email         = ["suman.chakravartula@ntti3.com"]
  gem.summary       = %q{A Fluentd buffered output plugin to send data from ESE to a HTTPS endpoint}
  gem.description   = gem.summary
  gem.homepage      = "https://github.com/cloudwan/fluent-plugin-out-ese-http"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_runtime_dependency "yajl-ruby", "~> 1.0"
  gem.add_runtime_dependency "fluentd", "~> 0.10.0"
  gem.add_development_dependency "bundler"
  gem.add_development_dependency "rake"
end
