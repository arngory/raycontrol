# Contributing

In Russian: [CONTRIBUTING.ru.md](CONTRIBUTING.ru.md). This text is the reference one; where the two differ, this one
holds.

In short: a short branch off `main` → a pull request → a green "CI result" check → a merge (squash). The owner releases
with a tag of their own. These rules are shared by the client and the server: the node's repositories (raycontrol,
niko-server and the forks) carry the same text, apart from the section "In this repository".

## Branches and pull requests

- `main` is protected: changes reach it only through a pull request with the checks "CI result" (`ci.yml`), "Commit
  messages" and "Secrets" (`checks.yml`) green; no force-push, no deletion. Only the owner can bypass the rule.
- A task gets a short branch of its own off a fresh `main`: `<area>/<short>`, for example `app/keepalive-obfs`,
  `ci/commit-checks`, `docs/structure`. A branch lives days, not weeks, and is deleted after the merge.
- The pull request is opened at once, as a draft if need be: the checks run on it, not on a push to the branch.
- The merge is a **squash**: the pull request's title and description become the commit message in `main`, so they
  follow the rules of a commit message (below). GitHub adds " (#N)" to the title: in the merge dialog, replace it with
  " (arngory/raycontrol#N)". Several independent changes are several pull requests; rebase instead of squash only when
  the commits inside make sense one by one.
- The author merges once the checks are green. The owner sees every pull request and may stop or revert it.
- The description template is `.github/pull_request_template.md`: what and why, how it was checked, what changes for
  the other side.

## Commit messages

```
<what changed, in English, present tense, up to 72 characters>

<why and how, lines up to ~110 characters; specifications by name: lan-v1 §3, api-v1.md §2>
```

- **No bare `#N`.** In a fork GitHub links `#N` to an issue of the parent repository: that is how Niko's commits ended
  up in other people's issues in MatsuriDayo/NekoBoxForAndroid. Write the full form `arngory/<repository>#N`, or
  "task N". "Commit messages" (`.github/scripts/bare-refs.py`) checks the commits, the title and the description of the
  pull request, again at each edit of them.
- Closing words (`fixes`, `closes`) only with the full form, and only where Issues are on.
- No `Co-Authored-By` and `Claude-Session` trailers (the owner's decision of 2026-11-18): who wrote a commit shows in
  its author. In the commits from before that day they stay until the history is cleaned before the MVP.
- No session link in the pull request's description either; the line "Generated with Claude Code" stays there (the
  owner's decision of 2026-11-18).
- Keep it short: a sentence or two a point. The details go in the specification or the code, not in the message.

## Secrets and data

- Keys, passwords, tokens and the addresses of real nodes never get into the repository. "Secrets" runs gitleaks over
  the commits of a pull request. A false finding (a test's throwaway key) goes into the allowlist of `.gitleaks.toml`
  (there is an example there), with a comment on where the key comes from, in a pull request of its own: the check
  takes `.gitleaks.toml` and `.gitleaksignore` from `main`, so the exception counts from the next pull request.
  `gitleaks:allow` comments are not taken.
- The "Commit messages" script and the rules and exceptions of "Secrets" are taken from `main`, and the Go that builds
  gitleaks is pinned in `checks.yml`. The workflows themselves run as they are in the pull request: a pull request that
  changes `.github/workflows/` changes its own checks too. The owner merges such a pull request of another contributor.
- The release signing key (minisign) lives only in the GitHub environment `release`, the IPinfo token in
  `release-data` (`docs/RELEASE.md`); the public key is pinned in `internal/release/release.go`. `docs/local/` is in
  `.gitignore`.
- Addresses in tests and examples are documentation ones only: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
  `2001:db8::/32`, the domains `*.example`, `*.test`. Data captured on nodes comes only from throwaway CI nodes.
- Private links (sessions, canvases, workspaces) do not go into the repository.

## Pins

Everything taken from another repository is pinned to an exact version: a commit, a tag, a Go pseudo-version or the
SHA-256 of a file.

- A pin changes in a pull request of its own titled like `Pin raycontrol v0.31.2 (…)`: what, to what, and why.
- Pin only a tag or a commit of a lasting branch (`main`, `niko` in the forks), not of a temporary branch: it may be
  deleted.
- Before pinning a server release, run the interop CI against it (a manual run with the new value, or a pull request
  with it).

## Release

1. `.github/release-notes/vX.Y.Z.md`: in English, then in Russian, no bare `#N`.
2. The owner puts the tag `vX.Y.Z` on a commit of `main` (the Releases page or git; only the owner can create a `v*`
   tag) and approves the environment `release`. The workflow takes the green CI of that commit on `main`, and runs the
   CI itself if there is none; govulncheck runs on the day of the release in any case. Then it builds the archives,
   signs `SHA256SUMS` and publishes the release. In detail: `docs/RELEASE.md`.

## In this repository

| What | Where |
|---|---|
| the node: daemon, perimeter, CLI | `cmd/rayd`, `cmd/rayspa`, `cmd/rayctl`; the code is in `internal/` |
| API and specifications | `api/` (proto, code from `scripts/gen.sh`); the contract with the client is `docs/spec/` |
| install and pins | `install/`, `deploy/` (`versions.env`: Xray, niko-server, slipstream-server) |
| tests | `go test ./...`; the full run is `.github/workflows/ci.yml` (netns, install containers, upgrade, relay) |
| release | `.github/workflows/release.yml`, `docs/RELEASE.md` |
| state with the client | `docs/handoff/SYNC.md` |

Differences from the shared rules:
- The server's session works on the lasting branch `claude/clever-feynman-w0e2v1` and branches named after it (its
  environment sets this), not on a short branch per task. A push to a branch does not start the CI by itself: a pull
  request (even a draft) is open while the branch has work in it.
- The merge is a merge commit, not a squash: SYNC and the release notes refer to the branch's commits, and they must
  stay in `main`. The merge title is `Merge arngory/raycontrol#N: <the pull request's title>`, without the bare `#N`
  GitHub puts by default.

Who pins raycontrol: the client (`.github/raycontrol.env`: tag and commit) and the client's interop CI against
`rayd -supervise`. niko-server is pinned here, in `deploy/versions.env`.
