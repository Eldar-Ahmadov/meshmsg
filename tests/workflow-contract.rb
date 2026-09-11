#!/usr/bin/env ruby
# frozen_string_literal: true

require "yaml"

ROOT = File.expand_path("..", __dir__)
WORKFLOWS = File.join(ROOT, ".github", "workflows")

class ContractError < StandardError; end

def assert(condition, message)
  raise ContractError, message unless condition
end

def load_workflow(name)
  path = File.join(WORKFLOWS, name)
  YAML.parse_file(path) # independent YAML syntax parse
  value = YAML.safe_load_file(path, aliases: false)
  assert(value.is_a?(Hash), "#{name} must contain a mapping")
  value
rescue Psych::Exception => e
  raise ContractError, "#{name} is invalid YAML: #{e.message}"
end

def triggers(workflow)
  workflow["on"] || workflow[true]
end

def deep_copy(value)
  Marshal.load(Marshal.dump(value))
end

def each_uses(value, path = [], &block)
  case value
  when Hash
    value.each do |key, child|
      block.call(child, path + [key]) if key == "uses"
      each_uses(child, path + [key], &block)
    end
  when Array
    value.each_with_index { |child, index| each_uses(child, path + [index], &block) }
  end
end

def step_by_id(job, id)
  matches = job.fetch("steps", []).select { |step| step["id"] == id }
  assert(matches.length == 1, "expected exactly one enabled step id #{id}")
  step = matches.first
  assert(![false, "false", "${{ false }}"].include?(step["if"]), "step #{id} must not be disabled")
  step
end

def assert_run(job, id, command)
  step = step_by_id(job, id)
  assert(step["run"]&.strip == command, "step #{id} command changed")
end

def assert_order(job, ids)
  actual = job.fetch("steps", []).filter_map { |step| step["id"] }
  positions = ids.map { |id| actual.index(id) }
  assert(positions.none?(&:nil?) && positions == positions.sort && positions.uniq.length == ids.length,
         "required step order changed: #{ids.join(' -> ')}")
end

def assert_exact_checkout(job, description)
  matches = job.fetch("steps", []).select { |step| step["uses"]&.start_with?("actions/checkout@") }
  assert(matches.length == 1, "#{description} must have exactly one checkout")
  checkout = matches.first
  assert(checkout.dig("with", "ref") == "${{ github.sha }}", "#{description} must check out exact event SHA")
  assert(checkout.dig("with", "persist-credentials") == false, "#{description} must not persist credentials")
end

def load_inventory
  File.readlines(File.join(ROOT, "tests", "linux-integration-inventory.tsv"), chomp: true).map do |line|
    fields = line.split("\t")
    assert(fields.length >= 3 && fields[0].match?(/\A[1-9][0-9]*\z/), "invalid integration inventory row")
    [fields[0].to_i, *fields[1..]]
  end
end

def validate(ci, verification, release, inventory)
  { "ci.yml" => ci, "verification.yml" => verification, "release.yml" => release }.each do |name, workflow|
    each_uses(workflow) do |uses, location|
      next if uses.start_with?("./.github/workflows/")
      assert(uses.match?(%r{\A[^/\s]+/[^/@\s]+@[0-9a-f]{40}\z}),
             "#{name} #{location.join('.')} action is not full-SHA pinned: #{uses}")
    end
  end

  assert(triggers(verification).keys == ["workflow_call"], "verification trigger must be workflow_call only")
  assert(verification["permissions"] == { "contents" => "read" }, "verification must be read-only")
  jobs = verification.fetch("jobs")
  expected_jobs = %w[workflow-contract rust-linux windows-rust dependency-policy linux-integration required]
  assert(jobs.keys.sort == expected_jobs.sort, "verification job inventory changed")
  (expected_jobs - ["required"]).each { |id| assert_exact_checkout(jobs[id], "verification #{id}") }
  assert(jobs.dig("required", "name") == "Reusable verification aggregate", "reusable aggregate name changed")
  assert(jobs.dig("required", "if") == "${{ always() }}", "reusable aggregate must run always")
  assert(jobs.dig("required", "needs").sort == (expected_jobs - ["required"]).sort,
         "reusable aggregate must need every gate")

  contract = jobs["workflow-contract"]
  assert_run(contract, "install-actionlint",
             "go install github.com/rhysd/actionlint/cmd/actionlint@914e7df21a07ef503a81201c76d2b11c789d3fca")
  assert_run(contract, "actionlint", '$(go env GOPATH)/bin/actionlint')
  assert_run(contract, "workflow-contract", "ruby tests/workflow-contract.rb\npython3 tests/release-contract-tests.py\npython3 tests/release-assets-tests.py\npython3 tests/github-protection-contract-tests.py")
  assert_order(contract, %w[install-actionlint actionlint workflow-contract])

  linux = jobs["rust-linux"]
  assert_run(linux, "rustfmt", "cargo fmt --all -- --check")
  assert_run(linux, "clippy", "cargo clippy --locked --all-targets -- -D warnings")
  assert_run(linux, "rust-tests", "cargo test --locked --all-targets")
  assert_run(linux, "rust-build", "cargo build --locked")
  assert_order(linux, %w[rustfmt clippy rust-tests rust-build])
  windows = jobs["windows-rust"]
  assert_run(windows, "windows-tests", "cargo test --locked --all-targets")
  assert_run(windows, "windows-clippy", "cargo clippy --locked --all-targets -- -D warnings")
  assert_run(windows, "windows-build", "cargo build --locked")
  assert_run(windows, "windows-resolve-dumpbin", "./tests/resolve-dumpbin.ps1")
  assert(step_by_id(windows, "windows-exercise-dumpbin").fetch("run").include?("/headers target/debug/meshmsg.exe"),
         "regular Windows verification must exercise the resolved dumpbin")
  assert_order(windows, %w[windows-tests windows-clippy windows-build windows-resolve-dumpbin windows-exercise-dumpbin])
  policy = jobs["dependency-policy"]
  assert_run(policy, "cargo-audit", "cargo audit")
  assert_run(policy, "cargo-deny", "cargo deny check advisories bans licenses sources")
  install_policy = policy.fetch("steps").find { |step| step["name"] == "Install pinned policy tools" }
  assert(install_policy&.fetch("run", "")&.lines&.map(&:strip)&.reject(&:empty?) == [
    "cargo install cargo-audit --version 0.22.2 --locked",
    "cargo install cargo-deny --version 0.20.2 --locked"
  ], "policy tool installation must remain exact and pinned")
  assert_run(jobs["linux-integration"], "integration-build", "cargo build --locked")
  assert_run(jobs["linux-integration"], "linux-integrations",
             "bash tests/run-linux-integrations.sh target/debug/meshmsg")
  assert(jobs.dig("linux-integration", "timeout-minutes") == 130, "integration job timeout must cover inventory")

  expected_inventory = [
    [60, "node", "tests/web-ui.cjs"],
    [60, "python3", "tests/integration-cli-errors.py", "{BIN}"],
    [180, "python3", "tests/integration-web.py", "{BIN}"],
    [600, "python3", "tests/integration-web-peer.py", "{BIN}"],
    [600, "python3", "tests/integration-peer-directory.py", "{BIN}"],
    [1100, "bash", "tests/integration-5-peer.sh", "{BIN}"],
    [600, "bash", "tests/integration-attachments.sh", "{BIN}"],
    [600, "bash", "tests/integration-direct-messages.sh", "{BIN}"],
    [600, "bash", "tests/integration-ipc-version-compat.sh", "{BIN}"],
    [600, "bash", "tests/integration-v018-message-boundary.sh", "{BIN}"],
    [600, "bash", "tests/integration-idempotency.sh", "{BIN}"],
    [60, "bash", "tests/integration-installer.sh", "{BIN}"]
  ]
  assert(inventory == expected_inventory, "parsed Linux integration inventory changed unexpectedly")
  assert(inventory.sum(&:first) <= 6900, "integration command budget exceeds 115 minutes")

  ci_on = triggers(ci)
  assert(ci_on.key?("pull_request") && ci_on.dig("push", "branches") == ["main"], "CI triggers changed")
  assert(ci["permissions"] == { "contents" => "read" }, "CI must be read-only")
  assert(ci.fetch("jobs").keys.sort == %w[required verification], "CI caller jobs changed")
  assert(ci.dig("jobs", "verification", "uses") == "./.github/workflows/verification.yml",
         "CI must call authoritative verification")
  caller_gate = ci.dig("jobs", "required")
  assert(caller_gate["name"] == "Required verification", "stable branch-protection context changed")
  assert(caller_gate["needs"] == "verification" && caller_gate["if"] == "${{ always() }}",
         "caller aggregate must always evaluate reusable verification")
  assert(caller_gate["permissions"] == {}, "caller aggregate must have no token permissions")

  assert(triggers(release) == { "push" => { "tags" => ["v*.*.*"] } }, "release trigger changed")
  assert(release["permissions"] == { "contents" => "read" }, "release default must be read-only")
  release_jobs = release.fetch("jobs")
  assert(release_jobs.dig("verification", "uses") == "./.github/workflows/verification.yml",
         "release must call authoritative verification")
  assert(release_jobs.dig("verification", "needs") == "validate-tag", "release verification ordering changed")
  assert(release_jobs.dig("validate-tag", "name") == "Initial release admission", "admission job evidence name changed")
  assert(release_jobs.dig("validate-tag", "permissions") == { "actions" => "read", "contents" => "read" },
         "only admission may read prior workflow attempt evidence")
  assert_run(release_jobs["validate-tag"], "release-eligibility",
             "bash tests/check-release-admission.sh \"$RELEASE_TAG\" \"$RELEASE_SHA\" \"$RUN_ID\" \"$RUN_ATTEMPT\"")
  %w[validate-tag audit-protections linux windows release].each { |id| assert_exact_checkout(release_jobs[id], "release #{id}") }
  assert(release_jobs.dig("audit-protections", "needs") == "verification", "live audit must follow verification")
  assert_run(release_jobs["audit-protections"], "live-protection-audit",
             "scripts/github-release-protections.sh --ci-check")
  assert(step_by_id(release_jobs["audit-protections"], "live-protection-audit").dig("env", "GH_TOKEN") ==
         "${{ secrets.RELEASE_PROTECTION_AUDIT_TOKEN }}", "pre-build audit token binding changed")
  %w[linux windows].each do |id|
    assert(release_jobs.dig(id, "needs") == "audit-protections", "#{id} build must follow live protection audit")
  end
  assert_order(release_jobs["linux"],
               %w[release-build-linux release-package-linux release-smoke-linux release-upload-linux])
  assert_run(release_jobs["linux"], "release-smoke-linux",
             "python3 tests/verify-release-assets.py --platform linux --tag \"$GITHUB_REF_NAME\" --dist dist --binary-root target --execute")
  linux_upload = step_by_id(release_jobs["linux"], "release-upload-linux")
  assert(linux_upload.dig("with", "name") == "release-linux" &&
         linux_upload.dig("with", "path").lines.map(&:strip).reject(&:empty?) == [
           "dist/meshmsg-${{ github.ref_name }}-x86_64-unknown-linux-gnu.tar.gz",
           "dist/meshmsg-${{ github.ref_name }}-x86_64-unknown-linux-musl.tar.gz"
         ], "Linux artifact upload names changed")
  assert_order(release_jobs["windows"],
               %w[release-build-windows release-package-windows release-resolve-dumpbin release-smoke-windows release-upload-windows])
  assert_run(release_jobs["windows"], "release-resolve-dumpbin", "./tests/resolve-dumpbin.ps1")
  windows_smoke = step_by_id(release_jobs["windows"], "release-smoke-windows").fetch("run")
  assert(windows_smoke.include?("verify-release-assets.py --platform windows") &&
         windows_smoke.include?("$env:DUMPBIN /dependents") && windows_smoke.include?("VCRUNTIME|MSVCP"),
         "Windows package/version/static-CRT smoke gate changed")
  windows_upload = step_by_id(release_jobs["windows"], "release-upload-windows")
  assert(windows_upload.dig("with", "name") == "release-windows" &&
         windows_upload.dig("with", "path") == "dist/meshmsg-${{ github.ref_name }}-x86_64-pc-windows-msvc.zip",
         "Windows artifact upload name changed")
  assert(release_jobs.dig("release", "needs").sort == %w[linux windows], "publisher dependencies changed")
  assert(release_jobs.dig("release", "permissions") == { "contents" => "write" }, "publisher needs contents:write")
  release_jobs.each do |id, job|
    next if %w[release validate-tag].include?(id)
    assert(job["permissions"].nil? || job["permissions"] == { "contents" => "read" }, "#{id} has excess permission")
  end
  publish = step_by_id(release_jobs["release"], "release-publish").fetch("run")
  assert(publish.scan('bash tests/check-release-eligibility.sh recheck "$tag" "$RELEASE_SHA"').length == 2,
         "historical-main recheck must run immediately before draft creation and publication")
  assert(publish.include?('gh release create "$tag" --draft --verify-tag --target "$RELEASE_SHA"'),
         "draft target is not exact-SHA bound")
  assert(publish.include?('gh release edit "$tag" --target "$RELEASE_SHA" --draft=false'),
         "published release target is not exact-SHA bound")
  assert(!publish.include?("--generate-notes"), "release notes must fail closed")
  linux_download = step_by_id(release_jobs["release"], "download-linux")
  windows_download = step_by_id(release_jobs["release"], "download-windows")
  assert(linux_download.dig("with", "name") == "release-linux" &&
         linux_download.dig("with", "path") == "incoming/linux", "publisher Linux download changed")
  assert(windows_download.dig("with", "name") == "release-windows" &&
         windows_download.dig("with", "path") == "incoming/windows", "publisher Windows download changed")
  assert_run(release_jobs["release"], "release-assets",
             "python3 tests/verify-release-assets.py --platform all --tag \"$RELEASE_TAG\" --incoming incoming --dist dist")
  assert_run(release_jobs["release"], "final-live-protection-audit",
             "scripts/github-release-protections.sh --ci-check")
  assert(step_by_id(release_jobs["release"], "final-live-protection-audit").dig("env", "GH_TOKEN") ==
         "${{ secrets.RELEASE_PROTECTION_AUDIT_TOKEN }}", "pre-publication audit token binding changed")
  assert(step_by_id(release_jobs["release"], "release-publish").dig("env", "RELEASE_PROTECTION_AUDIT_TOKEN") ==
         "${{ secrets.RELEASE_PROTECTION_AUDIT_TOKEN }}", "in-step final audit token binding changed")
  assert(publish.include?('GH_TOKEN="$RELEASE_PROTECTION_AUDIT_TOKEN" scripts/github-release-protections.sh --ci-check'),
         "live protections must be reaudited immediately before publication")
  assert_order(release_jobs["release"],
               %w[download-linux download-windows release-assets release-checksums final-live-protection-audit release-publish])
end

begin
  ci = load_workflow("ci.yml")
  verification = load_workflow("verification.yml")
  release = load_workflow("release.yml")
  inventory = load_inventory
  validate(ci, verification, release, inventory)

  mutations = {
    "commented/omitted actionlint gate" => lambda do |c, v, r, i|
      v["jobs"]["workflow-contract"]["steps"].reject! { |step| step["id"] == "actionlint" }
    end,
    "disabled Clippy gate" => lambda do |c, v, r, i|
      step_by_id(v["jobs"]["rust-linux"], "clippy")["if"] = false
    end,
    "renamed aggregate" => lambda do |c, v, r, i|
      c["jobs"]["required"]["name"] = "Old CI gate"
    end,
    "omitted integration" => lambda do |c, v, r, i|
      i.delete_at(10)
    end,
    "reordered smoke after upload" => lambda do |c, v, r, i|
      steps = r["jobs"]["linux"]["steps"]
      smoke = steps.index { |step| step["id"] == "release-smoke-linux" }
      upload = steps.index { |step| step["id"] == "release-upload-linux" }
      steps[smoke], steps[upload] = steps[upload], steps[smoke]
    end,
    "removed release verification" => lambda do |c, v, r, i|
      r["jobs"].delete("verification")
    end
  }
  mutations.each do |name, mutation|
    copies = [ci, verification, release, inventory].map { |value| deep_copy(value) }
    mutation.call(*copies)
    rejected = false
    begin
      validate(*copies)
    rescue ContractError
      rejected = true
    end
    raise ContractError, "mutation was not rejected: #{name}" unless rejected
  end
  puts "workflow contract and mutations: ok"
rescue ContractError => e
  warn "workflow contract failure: #{e.message}"
  exit 1
end
