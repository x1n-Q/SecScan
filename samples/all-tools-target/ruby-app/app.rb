SECRET = "demo_ruby_secret_for_static_scan_only"

def dangerous(cmd)
  system(cmd)
end

dangerous("echo sample") if ENV["RUN_SAMPLE"]
