# Verify a Release

Release verification is optional, but recommended before installing Guardian on
a production host. It answers three separate questions:

1. **Checksum:** did the archive arrive intact?
2. **GPG signature:** did Angie Guardian's release key sign that checksum list?
3. **Cosign signature:** does the published container digest carry Guardian's
   container signature?

Releases from 1.0.0 onward publish these verification files beside the two
Linux archives:

| File | Purpose |
|---|---|
| `SHA256SUMS` | SHA-256 digests for both archives and `cosign.pub` |
| `SHA256SUMS.asc` | Armored detached GPG signature over `SHA256SUMS` |
| `RELEASE-KEY.asc` | Public GPG key needed to verify the detached signature |
| `cosign.pub` | Public key needed to verify the container image |

The same files are attached to the GitLab and GitHub releases.

## Verify a Linux archive

Download the archive and all three GPG verification files into one directory.
Replace the version and architecture when needed:

```sh
VERSION=1.0.0
ARCH=amd64
BASE="https://github.com/AngieGuardian/angie-guardian/releases/download/${VERSION}"
ARCHIVE="angie-guardian-${VERSION}-linux-${ARCH}.tar.gz"

wget "${BASE}/${ARCHIVE}"
wget "${BASE}/SHA256SUMS"
wget "${BASE}/SHA256SUMS.asc"
wget "${BASE}/RELEASE-KEY.asc"
```

The public key is attached to the same release as the signature, so possession
of that file alone proves nothing. Compare its primary fingerprint with the
fingerprint published here:

```sh
gpg --show-keys --with-colons RELEASE-KEY.asc \
  | awk -F: '$1 == "fpr" { print $10; exit }'
```

The output must be exactly:

```text
E0C7C029005B0CE6A7438BD571D11FF23454B9D7
```

Import the checked public key, verify the detached signature, and only then
trust the checksum list:

```sh
gpg --import RELEASE-KEY.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

GPG must report a good signature whose primary fingerprint is
`E0C7 C029 005B 0CE6 A743 8BD5 71D1 1FF2 3454 B9D7`, and `sha256sum` must
report the archive as `OK`. A name, email address, short key ID, or merely
seeing “Good signature” is not a substitute for checking the full fingerprint.

`SHA256SUMS` also lists the other architecture and `cosign.pub`.
`--ignore-missing` deliberately skips files you did not download; it must still
print an `OK` line for the archive you intend to install. Any `BAD`, `FAILED`,
fingerprint mismatch, or signature error means stop and do not install it.

## Verify the container image

Install [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/),
then download `cosign.pub` plus the GPG verification files from the matching
release. Authenticate the Cosign key through the signed checksum list:

```sh
VERSION=1.0.0
BASE="https://github.com/AngieGuardian/angie-guardian/releases/download/${VERSION}"

wget "${BASE}/cosign.pub"
wget "${BASE}/SHA256SUMS"
wget "${BASE}/SHA256SUMS.asc"
wget "${BASE}/RELEASE-KEY.asc"

# First perform the fingerprint, import, and gpg --verify steps above.
sha256sum -c --ignore-missing SHA256SUMS
# cosign.pub: OK
```

The same image is published to GitLab's registry and GHCR. Pull the versioned
image from your preferred registry, resolve its immutable digest, and verify
that digest rather than trusting a mutable tag:

```sh
IMAGE="registry.melroy.org/melroy/angie-guardian:${VERSION}"
# Or: IMAGE="ghcr.io/angieguardian/angie-guardian:${VERSION}"
docker pull "$IMAGE"
REPOSITORY="${IMAGE%:*}"
IMAGE_DIGEST=$(docker image inspect \
  --format '{{range .RepoDigests}}{{println .}}{{end}}' "$IMAGE" \
  | grep -F "${REPOSITORY}@sha256:" | head -n1)

cosign verify --key cosign.pub "$IMAGE_DIGEST"
```

Cosign must report that the signature, image claims, and transparency-log
evidence verified. A registry may canonicalize the manifest differently, so
the GitLab and GHCR digest values can differ even though they serve the same
built image. Each registry therefore has its own digest and signature
attachment. Production manifests should use the verified `...@sha256:...`
reference for the chosen registry so a later move of `latest` cannot change
what gets deployed.

## Older releases

Releases before 1.0.0 publish `SHA256SUMS` but not the detached GPG signature
or Cosign key. Their checksums can detect an incomplete or corrupted download,
but cannot independently prove who published the checksum file.
