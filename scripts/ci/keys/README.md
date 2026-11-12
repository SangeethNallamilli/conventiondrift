# Pinned OpenPGP keys for T-003 CI

## kernelorg-autosigner.asc

Signs kernel.org `sha256sums.asc` files (the checksum autosigner). This is
**not** Junio C Hamano's personal Git-release key
(`96E0 7AF2 5771 9559 80DA  D100 20D0 4E5A 7136 60A7`).

Identified by running `gpg --verify` on the live
`https://www.kernel.org/pub/software/scm/git/sha256sums.asc` (clearsigned);
the signer RSA fingerprint is:

`B886 8C80 BA62 A1FF FAF5  FDA9 632D 3A06 589D A6B1`

Cross-checked against two independent sources (no keyserver use in CI):

1. Official kernel.org WKD for `autosigner@kernel.org`, the mechanism
   documented on https://www.kernel.org/signature.html (section "Using the
   Web Key Directory", and the "Kernel.org checksum autosigner and
   sha256sums.asc" section describing this dedicated key):
   `https://kernel.org/.well-known/openpgpkey/hu/ew8uiogxwri7d3fuioqgt7u1d5sngorx`
2. keys.openpgp.org by fingerprint
   `https://keys.openpgp.org/vks/v1/by-fingerprint/B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1`

The WKD key and the copy at
`https://mirrors.kernel.org/gentoo/distfiles/c2/autosigner@kernel.org.key`
were byte-identical.
