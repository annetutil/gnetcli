# Install the vendor-support skill

The `gnetcli-new-vendor` skill guides a coding agent through adding or reviewing
Gnetcli CLI profiles, registering `devtype`, and testing prompt, echo, error,
pager, and login handling. It is an instruction bundle, not a Go package or
a runtime device profile.

## Use with Codex in this repository

With Codex installed, clone the repository and start it from the checkout:

```sh
git clone https://github.com/annetutil/gnetcli.git
cd gnetcli
test -f .agents/skills/gnetcli-new-vendor/SKILL.md
codex
```

If you already have a checkout, use it instead of cloning again. Ensure your
branch contains `.agents/skills/gnetcli-new-vendor/`.

No separate skill installation is needed: Codex discovers repository skills
under `.agents/skills`. Run `/skills` to check availability, then invoke it
explicitly in a prompt:

```text
Use $gnetcli-new-vendor to add an AcmeOS CLI profile. Start by identifying
the required raw dialog samples and tests. Do not connect to real devices.
```

For a review:

```text
Use $gnetcli-new-vendor to review this PR for missing vendor support and
test coverage. Do not edit files or publish comments.
```

Codex can also select the skill automatically when a request matches its
description. If it does not appear, restart Codex from the checkout. Discovery
and invocation follow the [official Codex skills documentation](https://learn.chatgpt.com/docs/build-skills).

## Optional: make it available outside this checkout

On macOS or Linux, run this from the Gnetcli repository root to create a
user-level symlink. Keep the checkout in place while the link is installed.

```sh
skill_source="$(pwd)/.agents/skills/gnetcli-new-vendor"
skill_target="$HOME/.agents/skills/gnetcli-new-vendor"
test -f "$skill_source/SKILL.md" && {
    mkdir -p "$HOME/.agents/skills"
    if [ -e "$skill_target" ] || [ -L "$skill_target" ]; then
        printf 'Skill location already exists: %s\n' "$skill_target"
    else
        ln -s "$skill_source" "$skill_target"
    fi
}
```

Do not overwrite an existing installation blindly. The link follows changes
to the checkout; no separate copy needs updating. Repository and user-level
installations can both appear in the skill selector, so prefer repository-only
discovery when working on Gnetcli itself.

To remove only the user-level symlink:

```sh
unlink "$HOME/.agents/skills/gnetcli-new-vendor"
```

This does not remove the skill from the repository. Installing or invoking it
does not grant permission to modify real devices, publish changes, or deploy
services.
