#!/usr/bin/env ruby
# frozen_string_literal: true

require "json"
require "optparse"
require "pathname"
require "yaml"

module CallerIntegrity
  class ExternalTrustError < StandardError; end

  DECISION_ORDER = {
    "PASS" => 0,
    "WARN" => 1,
    "BLOCK" => 2,
    "SCANNER_ERROR" => 3,
    "POLICY_ERROR" => 4
  }.freeze

  Finding = Struct.new(:decision, :code, :file, :message, :remediation, keyword_init: true) do
    def to_h
      { decision:, code:, file:, message:, remediation: }
    end
  end

  module_function

  def evaluate(root:, changed_files:, policy_path:, approved_workflow_shas_raw:, repository: "unknown/consumer")
    policy = load_policy(policy_path)
    approved_workflow_shas = load_external_workflow_allowlist(approved_workflow_shas_raw)
    findings = []
    workflow_paths(root).each do |path|
      inspect_workflow(path, root, policy, approved_workflow_shas, findings, repository)
    end
    inspect_changed_files(changed_files, policy, findings)
    findings << Finding.new(
      decision: "PASS",
      code: "CALLER_INTEGRITY_OK",
      file: nil,
      message: "Caller workflows and changed paths satisfy the central integrity contract.",
      remediation: "No action required."
    ) if findings.empty?
    report(findings)
  rescue ExternalTrustError => e
    report([Finding.new(
      decision: "POLICY_ERROR",
      code: "EXTERNAL_WORKFLOW_ALLOWLIST_INVALID",
      file: nil,
      message: "The caller repository/organization workflow allowlist is unavailable or malformed: #{e.message}.",
      remediation: "Configure DEVSECOPS_APPROVED_WORKFLOW_SHAS as a JSON array of reviewed 40-character SHAs outside the PR."
    )])
  rescue JSON::ParserError => e
    report([Finding.new(
      decision: "POLICY_ERROR",
      code: "UNREADABLE_POLICY_INPUT",
      file: nil,
      message: "A workflow or trusted policy document is invalid: #{e.class}.",
      remediation: "Correct the malformed YAML/JSON; do not treat this run as a vulnerability result."
    )])
  rescue Errno::ENOENT, Errno::EACCES, IOError => e
    report([Finding.new(
      decision: "SCANNER_ERROR",
      code: "GUARD_RUNTIME_ERROR",
      file: nil,
      message: "The integrity guard could not read required input: #{e.class}.",
      remediation: "Retry the check and investigate checkout/runtime availability before publish or deploy."
    )])
  end

  def load_policy(path)
    policy = JSON.parse(File.read(path, encoding: "UTF-8"))
    required = %w[
      schema_version assurance_scope configuration_authority central_repository approved_reusable_workflows approved_actions approved_central_local_uses
      approved_action_runtimes guard_workflow allowed_permissions approved_privileged_jobs baseline_paths_exact untrusted_policy_paths_exact
      untrusted_policy_path_prefixes
    ]
    raise JSON::ParserError, "policy keys differ" unless policy.keys.sort == required.sort
    raise JSON::ParserError, "policy must declare detection-only assurance" unless policy["assurance_scope"] == "detection_contract"
    raise JSON::ParserError, "policy must declare mutable caller authority" unless policy["configuration_authority"] == "caller_write_actor"
    raise JSON::ParserError, "unsupported policy version" unless policy["schema_version"] == "1.0.0"
    policy["approved_actions"].each_value do |shas|
      raise JSON::ParserError, "approved action refs must be immutable SHAs" unless shas.all? { |sha| sha.match?(/\A[0-9a-f]{40}\z/) }
    end
    expected_action_refs = policy["approved_actions"].flat_map do |identity, shas|
      shas.map { |sha| "#{identity}@#{sha}" }
    end.sort
    runtime_refs = policy["approved_action_runtimes"].keys.sort
    raise JSON::ParserError, "action runtime attestations differ from approved refs" unless runtime_refs == expected_action_refs
    policy["approved_action_runtimes"].each_value do |runtime|
      unless runtime.is_a?(String) && runtime.match?(/\A(?:node\d+|composite|docker)\z/)
        raise JSON::ParserError, "action runtime attestation is invalid"
      end
    end
    policy["approved_privileged_jobs"].each_value do |jobs|
      raise JSON::ParserError, "privileged job policy must be a mapping" unless jobs.is_a?(Hash)
      jobs.each_value do |config|
        expected = %w[permissions reusable_workflow]
        raise JSON::ParserError, "privileged job keys differ" unless config.is_a?(Hash) && config.keys.sort == expected
        raise JSON::ParserError, "privileged workflow must be approved" unless policy["approved_reusable_workflows"].include?(config["reusable_workflow"])
        raise JSON::ParserError, "privileged permissions must be explicit" unless config["permissions"].is_a?(Hash) && !config["permissions"].empty?
      end
    end
    policy
  end

  def load_external_workflow_allowlist(raw)
    raise ExternalTrustError, "variable is missing" if raw.nil? || raw.strip.empty?
    shas = JSON.parse(raw)
    unless shas.is_a?(Array) && !shas.empty? && shas.uniq.length == shas.length &&
           shas.all? { |sha| sha.is_a?(String) && sha.match?(/\A[0-9a-f]{40}\z/) }
      raise ExternalTrustError, "expected a non-empty JSON array of unique full SHAs"
    end
    shas.freeze
  rescue JSON::ParserError => e
    raise ExternalTrustError, "invalid JSON: #{e.message}"
  end

  def workflow_paths(root)
    paths = Dir.glob(File.join(root, ".github", "workflows", "*.{yml,yaml}"), File::FNM_EXTGLOB).sort
    raise Errno::ENOENT, "no caller workflows found" if paths.empty?
    paths
  end

  def inspect_workflow(path, root, policy, approved_workflow_shas, findings, repository)
    relative = Pathname(path).relative_path_from(Pathname(root)).to_s
    # Central reusable implementations are reviewed policy sources, not caller input.
    # Excluding them only in the central repository avoids evaluating deliberate
    # classifier mechanics (for example continue-on-error followed by fail-closed
    # classification) as consumer bypasses. Every workflow in a consumer repository
    # is still inspected.
    if repository == policy["central_repository"]
      workflow_name = File.basename(relative)
      return if policy["approved_reusable_workflows"].include?(workflow_name)
    end
    if File.lstat(path).symlink?
      findings << finding("BLOCK", "WORKFLOW_SYMLINK", relative,
                          "Workflow path is a symbolic link and can obscure the reviewed source.",
                          "Replace the symlink with a regular workflow file committed at this exact path.")
      return
    end
    workflow = YAML.safe_load(File.read(path, encoding: "UTF-8"), permitted_classes: [], permitted_symbols: [], aliases: false)
    source = File.read(path, encoding: "UTF-8")
    unless workflow.is_a?(Hash) && workflow["jobs"].is_a?(Hash)
      findings << finding("POLICY_ERROR", "WORKFLOW_SCHEMA_INVALID", relative,
                          "Workflow must contain a jobs mapping.",
                          "Correct the workflow YAML structure before evaluating security decisions.")
      return
    end

    inspect_permissions(workflow["permissions"], relative, "workflow", policy, findings, required: true)
    workflow["jobs"].each do |job_name, job|
      unless job.is_a?(Hash)
        findings << finding("POLICY_ERROR", "JOB_SCHEMA_INVALID", relative,
                            "Job #{job_name} is not a mapping.",
                            "Correct the job YAML structure.")
        next
      end
      inspect_permissions(
        job["permissions"],
        relative,
        "job #{job_name}",
        policy,
        findings,
        required: false,
        job_name:,
        job:,
        approved_workflow_shas:
      )
      inspect_privileged_dependency(job, relative, job_name, policy, findings)
      inspect_continue_on_error(job, relative, "job #{job_name}", findings)
      inspect_inherited_secrets(job, relative, "job #{job_name}", findings)
      Array(job["steps"]).each_with_index do |step, index|
        next unless step.is_a?(Hash)
        inspect_continue_on_error(step, relative, "job #{job_name} step #{index + 1}", findings)
        inspect_secret_handling(step, relative, "job #{job_name} step #{index + 1}", findings)
        inspect_use(step["uses"], relative, "job #{job_name} step #{index + 1}", "action", policy, approved_workflow_shas, findings, repository) if step["uses"]
      end
      inspect_use(job["uses"], relative, "job #{job_name}", "workflow", policy, approved_workflow_shas, findings, repository) if job["uses"]
    end
    if source.match?(/^\s*pull_request_target\s*:/)
      findings << finding("BLOCK", "PULL_REQUEST_TARGET_FORBIDDEN", relative,
                          "Workflow uses pull_request_target, which runs with the trusted base context and can expose write-capable credentials to untrusted PR logic.",
                          "Use pull_request with read-only permissions; isolate any privileged follow-up in a separately reviewed workflow that never checks out PR code.")
    end
  rescue Psych::Exception => e
    findings << finding("POLICY_ERROR", "UNREADABLE_WORKFLOW_YAML", relative,
                        "Workflow YAML is invalid: #{e.class}.",
                        "Correct the malformed workflow; existing blockers remain valid and this error is not a vulnerability finding.")
  end

  def inspect_permissions(value, file, location, policy, findings, required:, job_name: nil, job: nil, approved_workflow_shas: [])
    if value.nil?
      return unless required
      findings << finding("BLOCK", "PERMISSIONS_NOT_EXPLICIT", file,
                          "#{location} permissions are implicit.",
                          "Declare `permissions: { contents: read }` or a stricter empty mapping.")
      return
    end
    unless value.is_a?(Hash)
      findings << finding("BLOCK", "EXCESSIVE_PERMISSIONS", file,
                          "#{location} uses broad permission shorthand.",
                          "Replace read-all/write-all with explicit `contents: read`.")
      return
    end
    normalized = value.transform_keys(&:to_s).transform_values(&:to_s)
    allowed = policy["allowed_permissions"]
    excessive = normalized.any? { |key, access| allowed[key] != access }
    return unless excessive
    return if approved_privileged_permissions?(
      normalized,
      file,
      job_name,
      job,
      policy,
      approved_workflow_shas
    )
    findings << finding("BLOCK", "EXCESSIVE_PERMISSIONS", file,
                        "#{location} exceeds the caller permission contract.",
                        "Remove write scopes. Privileged OIDC/write permissions are accepted only for an exact reviewed job declared in central policy and calling its approved SHA-pinned reusable workflow.")
  end

  def approved_privileged_permissions?(normalized, file, job_name, job, policy, approved_workflow_shas)
    return false unless job_name && job.is_a?(Hash)
    config = policy.dig("approved_privileged_jobs", file, job_name.to_s)
    return false unless config
    return false unless normalized == config["permissions"]

    reference = job["uses"]
    return false unless reference.is_a?(String)
    match = reference.match(%r{\A#{Regexp.escape(policy["central_repository"])}/\.github/workflows/([^@]+)@([0-9a-f]{40})\z})
    return false unless match

    workflow_name, ref = match.captures
    workflow_name == config["reusable_workflow"] && approved_workflow_shas.include?(ref)
  end

  def inspect_privileged_dependency(job, file, job_name, policy, findings)
    config = policy.dig("approved_privileged_jobs", file, job_name.to_s)
    return unless config

    dependencies = case job["needs"]
                   when String
                     [job["needs"]]
                   when Array
                     job["needs"]
                   else
                     []
                   end
    return if dependencies.all? { |dependency| dependency.is_a?(String) } && dependencies.include?("integrity")

    findings << finding(
      "BLOCK",
      "PRIVILEGED_JOB_NOT_GATED",
      file,
      "Privileged job #{job_name} can start before the caller integrity decision.",
      "Declare `needs: integrity` (or include `integrity` in the needs array) so an unapproved rollback cannot execute privileged reusable workflow code."
    )
  end

  def inspect_continue_on_error(value, file, location, findings)
    return unless value.key?("continue-on-error")
    return if value["continue-on-error"] == false
    findings << finding("BLOCK", "CONTINUE_ON_ERROR_BYPASS", file,
                        "#{location} can neutralize a failed control.",
                        "Remove `continue-on-error`; preserve evidence with `if: always()` on upload steps instead.")
  end

  def inspect_inherited_secrets(job, file, location, findings)
    return unless job["secrets"].to_s == "inherit"
    findings << finding("BLOCK", "SECRETS_INHERIT_FORBIDDEN", file,
                        "#{location} forwards every available secret to another workflow.",
                        "Remove `secrets: inherit`. A PR validation workflow must be secretless; pass only an explicitly reviewed credential to a privileged post-merge workflow.")
  end

  def inspect_secret_handling(step, file, location, findings)
    command = step["run"]
    return unless command.is_a?(String)

    if command.match?(/\$\{\{[^}]*\bsecrets\.[A-Za-z0-9_]+/m)
      findings << finding("BLOCK", "SECRET_EXPRESSION_IN_RUN", file,
                          "#{location} interpolates a GitHub secret directly into shell source, where tracing, quoting or generated files can expose it.",
                          "Keep PR validation secretless. For an approved post-merge job, bind one named secret through `env` and never print, archive or serialize it.")
    end

    secret_env_names = if step["env"].is_a?(Hash)
                         step["env"].filter_map do |name, value|
                           name.to_s if value.to_s.match?(/\$\{\{[^}]*\bsecrets\.[A-Za-z0-9_]+/m)
                         end
                       else
                         []
                       end
    return if secret_env_names.empty?

    names_pattern = secret_env_names.map { |name| Regexp.escape(name) }.join("|")
    exfiltration = command.match?(
      /(?:echo|printf|printenv|env|set|jq|base64|tee|cat|curl|wget|nc|tar|zip).*(?:\$(?:#{names_pattern})|\$\{(?:#{names_pattern})\})/mi
    )
    return unless exfiltration

    findings << finding("BLOCK", "SECRET_EXFILTRATION_PATTERN", file,
                        "#{location} sends a secret-backed environment variable to an output, serializer, network or archive command.",
                        "Remove the data flow. Use a purpose-built SHA-pinned authentication action with OIDC/keyless identity and keep credentials out of logs and artifacts.")
  end

  def inspect_use(reference, file, location, kind, policy, approved_workflow_shas, findings, repository)
    unless reference.is_a?(String)
      findings << finding("POLICY_ERROR", "USES_VALUE_INVALID", file,
                          "#{location} uses value is not a string.",
                          "Use an exact owner/repository/path@40-character-SHA reference.")
      return
    end
    if reference.start_with?("./")
      approved_local_uses = policy["approved_central_local_uses"].fetch(file, [])
      if repository == policy["central_repository"] && approved_local_uses.include?(reference)
        return
      end
      findings << finding("BLOCK", "LOCAL_USE_NOT_APPROVED", file,
                          "#{location} uses a local path not approved for this exact central workflow source.",
                          "Use an exact source+local-use pair from central policy, or move consumer code to a reviewed SHA-pinned identity.")
      return
    end

    match = reference.match(/\A([^@]+)@(.+)\z/)
    unless match
      findings << finding("POLICY_ERROR", "USES_REF_UNPARSABLE", file,
                          "#{location} has an invalid uses reference.",
                          "Use an allowlisted owner/repository/path with a full 40-character SHA.")
      return
    end
    identity = match[1]
    ref = match[2]
    unless ref.match?(/\A[0-9a-f]{40}\z/)
      code = kind == "workflow" ? "MUTABLE_WORKFLOW_REF" : "MUTABLE_ACTION_REF"
      findings << finding("BLOCK", code, file,
                          "#{location} references #{identity} with a mutable or non-SHA ref.",
                          "Pin the reviewed identity by its full 40-character commit SHA.")
      return
    end

    if kind == "workflow"
      prefix = "#{policy['central_repository']}/.github/workflows/"
      unless identity.start_with?(prefix)
        findings << finding("BLOCK", "UNAPPROVED_REUSABLE_WORKFLOW", file,
                            "#{location} calls a reusable workflow outside the trusted central identity.",
                            "Use an approved workflow from #{policy['central_repository']} at an allowlisted SHA.")
        return
      end
      workflow_name = identity.delete_prefix(prefix)
      unless !workflow_name.include?("/") && policy["approved_reusable_workflows"].include?(workflow_name)
        findings << finding("BLOCK", "UNAPPROVED_REUSABLE_WORKFLOW", file,
                            "#{location} calls an unapproved central workflow path.",
                            "Use an exact reusable workflow identity from the central allowlist.")
        return
      end
      return if approved_workflow_shas.include?(ref)
      findings << finding("BLOCK", "WORKFLOW_SHA_NOT_APPROVED", file,
                          "#{location} references an immutable but unapproved central SHA.",
                          "Use a SHA from the reviewed central allowlist; request review before adding a new release.")
      return
    end

    if identity == "actions/upload-artifact" && repository != policy["central_repository"]
      findings << finding("BLOCK", "CONSUMER_ARTIFACT_UPLOAD_FORBIDDEN", file,
                          "#{location} can publish caller-controlled files outside the ephemeral runner.",
                          "Remove the artifact upload. Expose PR feedback through summaries and annotations; only the reviewed central scan-to-publish contract may export its exact image subject.")
      return
    end

    approved_shas = policy["approved_actions"][identity]
    unless approved_shas
      findings << finding("BLOCK", "UNAPPROVED_ACTION_IDENTITY", file,
                          "#{location} references an Action outside the trusted identity allowlist.",
                          "Use an approved Action identity or add it through central security review.")
      return
    end
    if approved_shas.include?(ref)
      runtime = policy["approved_action_runtimes"].fetch("#{identity}@#{ref}")
      if runtime.start_with?("node") && runtime != "node24"
        findings << finding(
          "SCANNER_ERROR",
          "ACTION_RUNTIME_UNSUPPORTED",
          file,
          "#{location} resolves to JavaScript Action runtime #{runtime}; the supported runtime is node24.",
          "Upgrade to a reviewed SHA whose action metadata declares `runs.using: node24`, update the central runtime attestation, and rerun before the deprecated runtime breaks."
        )
      end
      return
    end
    findings << finding("BLOCK", "ACTION_SHA_NOT_APPROVED", file,
                        "#{location} references an immutable but unapproved Action SHA.",
                        "Pin a reviewed Action SHA from the central allowlist.")
  end

  def inspect_changed_files(changed_files, policy, findings)
    files = changed_files.filter_map do |path|
      normalize_changed_path(path)
    rescue ArgumentError => e
      findings << finding("POLICY_ERROR", "CHANGED_PATH_INVALID", nil, e.message,
                          "Remove malformed/escaping paths and retry from a clean Git diff.")
      nil
    end.uniq
    baselines = files.select { |path| policy["baseline_paths_exact"].include?(path) }
    policy_overrides = files.select do |path|
      policy["untrusted_policy_paths_exact"].include?(path) ||
        policy["untrusted_policy_path_prefixes"].any? { |prefix| path.start_with?(prefix) }
    end

    policy_overrides.each do |path|
      findings << finding("BLOCK", "LOCAL_POLICY_OVERRIDE", path,
                          "Consumer change attempts to replace or suppress central policy.",
                          "Move rule changes to the reviewed central policy repository and consume an approved SHA.")
    end

    baselines.each do |path|
      other_changes = files - baselines
      code = other_changes.empty? ? "BASELINE_CHANGE_REQUIRES_TRUST" : "BASELINE_AND_CHANGE_SAME_PR"
      message = if other_changes.empty?
                  "Consumer baseline changes require a separate trusted approval flow."
                else
                  "Baseline and application/workflow changes occur in the same PR and cannot self-approve risk."
                end
      findings << finding("BLOCK", code, path, message,
                          "Revert the baseline edit. Submit baseline maintenance through a separate trusted process using base-SHA evidence.")
    end
  end

  def normalize_changed_path(path)
    raise ArgumentError, "changed path contains NUL" if path.include?("\0")
    raise ArgumentError, "changed path is empty" if path.empty?
    pathname = Pathname(path)
    raise ArgumentError, "changed path must be repository-relative: #{path.inspect}" if pathname.absolute?
    normalized = pathname.cleanpath.to_s
    if normalized == "." || normalized == ".." || normalized.start_with?("../")
      raise ArgumentError, "changed path escapes repository root: #{path.inspect}"
    end
    normalized
  end

  def finding(decision, code, file, message, remediation)
    Finding.new(decision:, code:, file:, message:, remediation:)
  end

  def report(findings)
    decision = findings.max_by { |item| DECISION_ORDER.fetch(item.decision) }.decision
    {
      schema_version: "1.0.0",
      decision:,
      findings: findings.map(&:to_h),
      platform_limits: [
        "INT-01, INT-05 and INT-06 require required checks, rulesets or branch protection.",
        "Every central reusable, including this guard, must be present in caller var DEVSECOPS_APPROVED_WORKFLOW_SHAS."
      ]
    }
  end

  def emit_github_feedback(result)
    if ENV["GITHUB_OUTPUT"]
      File.open(ENV.fetch("GITHUB_OUTPUT"), "a", encoding: "UTF-8") do |output|
        output.puts "decision=#{result.fetch(:decision)}"
      end
    end

    if ENV["GITHUB_STEP_SUMMARY"]
      File.open(ENV.fetch("GITHUB_STEP_SUMMARY"), "a", encoding: "UTF-8") do |summary|
        summary.puts "## Caller integrity — `#{result.fetch(:decision)}`"
        summary.puts
        result.fetch(:findings).each do |item|
          location = item.fetch(:file) ? " (`#{item.fetch(:file)}`)" : ""
          summary.puts "- **#{item.fetch(:code)}**#{location}: #{item.fetch(:message)}"
          summary.puts "  - Remediation: #{item.fetch(:remediation)}"
        end
        summary.puts
        summary.puts "### Platform limits"
        result.fetch(:platform_limits).each { |limit| summary.puts "- #{limit}" }
      end
    end

    result.fetch(:findings).each do |item|
      next if item.fetch(:decision) == "PASS"
      command = item.fetch(:decision) == "WARN" ? "warning" : "error"
      properties = item.fetch(:file) ? " file=#{escape_command(item.fetch(:file))}" : ""
      message = "#{item.fetch(:code)}: #{item.fetch(:message)} Remediation: #{item.fetch(:remediation)}"
      puts "::#{command}#{properties}::#{escape_command(message)}"
    end
  end

  def escape_command(value)
    value.to_s.gsub("%", "%25").gsub("\r", "%0D").gsub("\n", "%0A").gsub(":", "%3A").gsub(",", "%2C")
  end
end

if $PROGRAM_NAME == __FILE__
  options = {}
  OptionParser.new do |parser|
    parser.on("--root PATH") { |value| options[:root] = value }
    parser.on("--changed-files PATH") { |value| options[:changed_files] = value }
    parser.on("--policy PATH") { |value| options[:policy] = value }
    parser.on("--output PATH") { |value| options[:output] = value }
    parser.on("--repository OWNER/REPO") { |value| options[:repository] = value }
  end.parse!

  required = %i[root changed_files policy output]
  abort "missing required options: #{(required - options.keys).join(', ')}" unless (required - options.keys).empty?
  changed_files = File.binread(options[:changed_files]).split("\0", -1).reject(&:empty?)
  repository = options.fetch(:repository, "unknown/consumer")
  approved_workflow_shas_raw = ENV["DEVSECOPS_APPROVED_WORKFLOW_SHAS"]
  result = CallerIntegrity.evaluate(
    root: options[:root],
    changed_files:,
    policy_path: options[:policy],
    approved_workflow_shas_raw:,
    repository:
  )
  File.write(options[:output], JSON.pretty_generate(result) + "\n", mode: "w", encoding: "UTF-8")
  CallerIntegrity.emit_github_feedback(result)
  puts JSON.generate(result)
  exit(%w[PASS WARN].include?(result[:decision]) ? 0 : 1)
end
