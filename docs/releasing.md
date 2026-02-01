# Releasing

To publish a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Pushing a `v*` tag triggers the GitHub Actions release workflow, which builds binaries and uploads the release assets.
