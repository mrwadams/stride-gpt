# Releasing STRIDE-GPT

Releases are automated by [`.github/workflows/release.yml`](.github/workflows/release.yml).
Pushing a version tag (`vX.Y.Z`) runs the full pipeline: verify the tag matches
the packaged version, run the test suite on Python 3.12/3.13/3.14, publish the
CLI to PyPI, build and push the multi-arch UI image to Docker Hub, then cut a
GitHub Release with generated notes.

## One-time setup

These configure the credentials the workflow relies on. Do them once.

### PyPI trusted publishing (no token)

The workflow publishes via OIDC, so there is no API token to manage. Add a
trusted publisher on PyPI instead:

1. Go to the [`stride-gpt` project on PyPI](https://pypi.org/manage/project/stride-gpt/settings/publishing/)
   → Publishing → Add a new trusted publisher (GitHub).
2. Fill in:
   - **Owner**: `mrwadams`
   - **Repository name**: `stride-gpt`
   - **Workflow name**: `release.yml`
   - **Environment name**: `pypi`
3. In the GitHub repo, create an Environment named `pypi`
   (Settings → Environments → New environment). Optionally add a required
   reviewer so a human approves each publish.

### Docker Hub secrets

The UI image publishes to the public `mrwadams/stridegpt` repository (free tier
covers public pushes). Add two repository secrets under
Settings → Secrets and variables → Actions:

- `DOCKERHUB_USERNAME` — your Docker Hub username (`mrwadams`).
- `DOCKERHUB_TOKEN` — a Docker Hub **access token** with Read/Write scope
  (Account Settings → Personal access tokens → Generate).

## Cutting a release

1. Bump `version` in `pyproject.toml`.
2. Add the release notes to the top of `README.md` and update any version-pinned
   references (e.g. `docker pull mrwadams/stridegpt:latest` examples stay
   correct automatically; the `latest` tag is republished each release).
3. Commit on `master` (via PR), then tag and push:

   ```bash
   git checkout master && git pull --ff-only
   git tag v0.19.0
   git push origin v0.19.0
   ```

   The tag must match `pyproject.toml` exactly, or the `verify` job fails before
   anything is published.

4. Watch the run under the repo's Actions tab. On success:
   - `stride-gpt X.Y.Z` is live on PyPI (`pip install stride-gpt`).
   - `mrwadams/stridegpt:X.Y.Z`, `:X.Y`, and `:latest` are pushed (amd64 + arm64).
   - A GitHub Release for the tag exists with auto-generated notes.

## Notes

- **Concurrency** is set to never cancel an in-flight release; a partially
  published tag is worse than waiting.
- **arm64** builds run under QEMU emulation and are slower than amd64. This is
  expected for the infrequent release cadence.
- To re-run a failed release, fix the cause and re-push the tag
  (`git tag -d vX.Y.Z && git push --delete origin vX.Y.Z`, then re-tag). PyPI
  will reject a re-upload of an already-published version, so bump the version
  if the PyPI step already succeeded.
