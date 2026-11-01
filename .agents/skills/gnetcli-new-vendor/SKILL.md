---
name: gnetcli-new-vendor
description: >-
  Add and extend network vendor and OS-family support in Gnetcli: Go CLI
  drivers, prompt/echo/pager/login handling, error detection, devtype
  registration, and mock tests. Use for requests to add a vendor, implement
  a device driver, support a new OS or firmware, fix vendor-specific CLI
  interactions, or review the completeness of a new profile in a PR.
  Do not use for device queries alone, monitoring configuration, network
  configuration changes, or service deployment.
---

# Add vendor support to Gnetcli

Implement the smallest necessary CLI/OS profile using actual device dialogs and
contracts from the current checkout. One manufacturer can have several different
CLIs: reuse a shared profile only when compatibility has been established.

## Sources and inputs

1. Locate the Gnetcli checkout and read `AGENTS.md`. When the skill is installed
   at `<gnetcli>/.agents/skills/gnetcli-new-vendor`, the repository root is three
   levels above the skill directory. Otherwise, use the path supplied by the user
   and verify the `github.com/annetutil/gnetcli` module in `go.mod`.
2. Inspect current changes to avoid overwriting other work. Clarify missing
   information that affects implementation: OS and versions, transport, required
   operations, the new `devtype` name, and sample output. Do not block local tests
   on hardware availability or change the SDK/protobuf API unnecessarily.
3. Collect or request **sanitized raw bytes**, not just screenshots: banner/login,
   prompts in every required mode, echo, successful output, syntax/permission
   errors, pagers, and questions. Preserve differences in `\r`, `\n`, ANSI
   sequences, spaces, and observed data-arrival boundaries.
4. Use an available scoped `ast-index` for navigation, but verify implementation,
   contracts, and registration. If the index is unavailable or incomplete, bounded
   text searches within selected packages are valid. Do not rebuild the index
   for every edit.

## Implementation

Read [Gnetcli CLI drivers](references/gnetcli.md) and the closest working example.
Check documentation against current signatures: older examples may contain
outdated mock helper paths, interfaces, or YAML feature names.

- For conventional CLIs, prefer `genericcli.MakeGenericCLI` and an existing
  connector. A new vendor does not inherently require a new transport.
- Decide whether the task needs a separate `pkg/device/<vendor>/` package, a
  profile within an existing family, or an external YAML prototype. Do not
  substitute external YAML for a requested built-in Go driver.
- For built-in selection by the CLI/server, register `devtype` in
  `pkg/devconf/devconf.go:InitDefaultDeviceMapping`. A constructor alone is not
  enough for that use case; library-only usage does not require the mapping.
- Do not work around an incorrect prompt with `any_echo`, broad regexes, or
  globally increased timeouts. Reproduce the byte-level dialog and identify
  the failing stage first.
- Preserve public output/error/status contracts, cancellation, and limits on
  repeated answers. A zero status does not prove that all output was preserved.
- When reusing error/login/pager handling from a related profile, verify it with
  data from the new OS. Matching prompt syntax does not establish dialog
  compatibility.

## Verification

- Regexes need positive and negative cases; behavior needs mock dialogs through
  the public `Device` interface. Assert exact results, not merely the absence
  of a Go error. Do not add tests for private methods.
- Verify that prompt-like output neither truncates nor consumes data, including
  text with an unclosed parenthesis before a configuration prompt. Restrict
  hostname and submode patterns so they cannot consume CR/LF unless those bytes
  belong to the explicit structure of an intentionally multiline prompt.
- Cover separately arriving echo/prompt data, consecutive commands in one
  session, initialization without unsupported mandatory commands, and the
  pager/question/login variants actually used. Do not add capabilities without
  evidence that the device needs them.
- Check the new OS's errors and exact `Output()/Error()/Status()` values: a device
  error message must not be returned as successful data.
- Run the relevant focused, race, and broader Go tests from the reference. Do not
  change dependencies to work around an unrelated test-environment failure.
- For reviews, read the PR description, the complete diff, and the actual profile
  tests. Green CI does not prove that the new constructor is covered. Distinguish
  new regressions, inherited gaps, and missing evidence. Run reproductions in a
  separate temporary copy without changing the working checkout. Do not publish
  comments unless requested.

## Action boundaries and result

Do not use a production device as a unit test. Query real devices only within
an agreed scope. A request to add support does not authorize configuration
changes, reboot, force-attach, publication, push, or deployment. Do not add
credentials, private addresses, or unsanitized output to fixtures, logs, or
example command arguments.

Briefly report the profile/devtype, supported OS versions and operations,
registration changes, checks actually completed, and limitations. State
separately whether real hardware was tested. Do not describe an upstream change
as already released or deployed, or treat missing validation details as proof
that the author did not perform validation.
