# Development

Contributor and maintainer guide for vex-reader. End-user install and usage
live in the [README](../README.md). For running tests, see [TESTING.md](TESTING.md).

Contributions are welcome. The tool works predominantly with Red Hat's VEX
files and has limited success with other formats (such as Cisco). If parsing
fails for a VEX file you care about, submit a patch or open an issue and link
to that file.

Sample VEX documents: https://wid.cert-bund.de/.well-known/csaf-aggregator/aggregator.json

## Development setup

Requires [uv](https://docs.astral.sh/uv/).

```shell
git clone https://github.com/vdanen/vex-reader.git
cd vex-reader
uv sync
```

From a checkout:

```shell
uv run vex-reader --vex tests/cve-2002-0803.json
```

Common Make targets: `make help`, `make test`, `make lint`, `make build`.

## Releasing

New releases use `v*` tags (for example `v0.9.6`). Historical tags such as
`0.9.5` remain as-is. The release workflow only publishes if the tagged commit
is already on `main` (so a tag pushed before the PR merges will fail until
you re-run the job or re-push the tag after merge).

`main` is protected: do **not** push commits directly to it. Use `develop` and
a PR.

1. On `develop`, bump the version (creates a commit and local tag):

   ```shell
   git checkout develop
   git pull
   make version VERSION=0.9.6
   ```

2. Push the version-bump commit on `develop` (not the tag yet, or the first
   release run will fail until `main` has that commit):

   ```shell
   git push origin develop
   ```

3. Open a PR `develop` → `main` on GitHub and merge it.

4. After the merge, push the tag (the tagged commit is now on `main`):

   ```shell
   git push origin v0.9.6
   ```

   If you pushed the tag earlier and the Release job failed the “on main”
   check, either **Re-run** that failed workflow after the merge, or delete and
   re-push the tag.

5. GitHub Actions runs [`.github/workflows/release.yml`](../.github/workflows/release.yml),
   verifies the tag is on `main`, builds the package, and publishes to PyPI with
   [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC; no API token).

6. If the `pypi` GitHub Environment has required reviewers, open the
   [Actions](https://github.com/vdanen/vex-reader/actions) run for that tag and
   **Approve** the deployment when prompted.

7. Confirm the new version on https://pypi.org/project/vex-reader/

`make upload` (twine) is an emergency fallback only.

### One-time Trusted Publishing setup

Do this once per repository (already done for this project; kept here for
reference).

#### GitHub Environment `pypi`

1. Open https://github.com/vdanen/vex-reader → **Settings** → **Environments**.
2. Click **New environment**, name it `pypi`, then **Configure environment**.
3. Optionally enable **Required reviewers** (add yourself) and restrict
   deployment tags to `v*`.
4. Do not add PyPI tokens as environment secrets; OIDC replaces them.

Docs: [Managing environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

#### PyPI Trusted Publisher

1. Log in to https://pypi.org → **Your projects** → **vex-reader** → **Manage**.
2. Open **Publishing**.
3. Under GitHub, add a publisher with:

   | Field | Value |
   |-------|--------|
   | Owner | `vdanen` |
   | Repository name | `vex-reader` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

4. After the first successful Trusted Publish, revoke any old long-lived PyPI
   API tokens used only for twine uploads.

Docs: [Adding a Trusted Publisher](https://docs.pypi.org/trusted-publishers/adding-a-publisher/).
