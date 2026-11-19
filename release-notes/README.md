# Release notes

One file per release, `vX.Y.Z.md`: the text of its GitHub release.

To release, raise the version in `symbolon-flutter/pubspec.yaml`,
`symbolon-extension/manifest.json` and README.md's status line, add
`vX.Y.Z.md` here, and merge to master. `.github/workflows/release.yml` then
publishes the release with the extension attached and runs the APK build,
which attaches the signed APK. Attach the Linux binaries by hand when the
agent changed.
