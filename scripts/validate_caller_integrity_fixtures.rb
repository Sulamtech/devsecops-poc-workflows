#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require_relative "caller_integrity_guard"

root = File.expand_path("..", __dir__)
fixtures_root = File.join(root, "fixtures", "caller-integrity")
manifest = JSON.parse(File.read(File.join(fixtures_root, "manifest.json"), encoding: "UTF-8"))
default_policy = File.join(root, "policy-pack", "v1", "caller-integrity-policy.json")
default_workflow_allowlist = [
  "ad9d553563cb027877f2c676cab7894bb095edc6",
  "e81bb14dbdcac024b92d524ad3ee7edcdae354d8",
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
]

failures = []
manifest.fetch("cases").each do |test_case|
  case_root = File.join(fixtures_root, test_case.fetch("fixture_root"))
  changed_files = test_case.fetch("changed_files")
  repository = test_case.fetch("repository", "Example/consumer")
  policy = if test_case["policy_fixture"]
             File.join(fixtures_root, "policies", test_case.fetch("policy_fixture"))
           else
             default_policy
           end
  allowlist_value = test_case.key?("approved_workflow_shas") ? test_case["approved_workflow_shas"] : default_workflow_allowlist
  approved_workflow_shas_raw = allowlist_value.nil? ? nil : JSON.generate(allowlist_value)
  result = CallerIntegrity.evaluate(
    root: case_root,
    changed_files:,
    policy_path: policy,
    approved_workflow_shas_raw:,
    repository:
  )
  actual_codes = result.fetch(:findings).map { |finding| finding.fetch(:code) }
  expected_codes = test_case.fetch("expected_codes")
  unless result.fetch(:decision) == test_case.fetch("expected_decision") && (expected_codes - actual_codes).empty?
    failures << "#{test_case.fetch('id')}: expected #{test_case.fetch('expected_decision')}/#{expected_codes}, got #{result.fetch(:decision)}/#{actual_codes}"
  end
end

abort failures.join("\n") unless failures.empty?
puts "caller-integrity fixtures: #{manifest.fetch('cases').length} cases passed"
