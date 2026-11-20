# ADR 0001: custom binary container instead of ZIP/tar for `.sers`

Status: accepted (implemented, NOT VERIFIED).

The specification sketches a directory-like layout. Implementing it as a ZIP
or tar archive imports a large attack surface: path traversal, symlinks,
duplicate entries, central-directory confusion, decompression bombs, parser
differentials.

Decision: a single binary container (header, signature, JSON manifest, module
data). Modules are addressed by id and by byte range declared in the signed
manifest. There are no paths and no compression, so those classes of attack do
not exist. The manifest is parsed only after its signature verified against a
publisher key the verifier already trusts.

Consequences: standard archive tools cannot open a `.sers` file (the
`sers-inspector` tool must do it); logical entries from the sketch
(`metadata/`, `integrity/hashes.json`) live inside the one signed manifest.
Integrity is a per-module hash list covered by the manifest signature, not a
Merkle tree: modules are decrypted whole, so partial verification of large
modules is not needed yet. Revisit if streaming decryption is added.
