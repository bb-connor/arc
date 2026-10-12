# Corresponding source for the security evidence APK closure

`../security-evidence-apks/` holds 203 signed Alpine 3.22 x86_64 archives that
`Dockerfile.security-evidence-runner` installs offline. This directory holds
the material needed to study, rebuild and modify them, in the same repository
and at the same commit as the archives:

- `recipes/<origin>/`: the exact aports recipe (APKBUILD, Alpine patches,
  install scripts, configuration files) of all 52 Alpine origins, taken from
  `https://gitlab.alpinelinux.org/alpine/aports` at the commit each archive's
  `.PKGINFO` names, byte for byte (each file matches its git blob id).
- `sources/<origin>/`: the unmodified upstream sources of all 51 origins that
  have any (104 files, one of them split into chunks; build-base has none).
  Each file's sha512 equals the value in that origin's APKBUILD
  `sha512sums`. `MANIFEST.json` keeps the URL each was fetched from, its
  length, sha256 and sha512, and `fetched_from` (the upstream URL, or the
  Alpine distfiles mirror for ncurses, whose upstream URL had gone).
- `build-tools/abuild/<revision>/` and `build-tools/abuild/sources/`: the
  recipe and source of the five abuild revisions (3.15.0_rc3-r0, -r1, -r3,
  3.15.0-r0, -r1) recorded in the archives' `.PKGINFO`, which ran the
  APKBUILDs. The `.PKGINFO` names the abuild version only; each revision's
  commit is the single 3.22-stable aports commit whose `main/abuild`
  APKBUILD carries that version.
- `aports-objects/<id>`: raw git commit and tree objects (222 objects,
  3,372,230 bytes) leading from each aports commit to its package directory.
  The checker hashes each object to its id and requires the package tree to
  list exactly the recipe files with their blob ids and modes. Six recipe
  files are git symlinks (mode 120000) and are kept as the link-target text
  git stores for them.
- `licenses/<origin>/`: license and notice files copied unchanged from the
  upstream sources of 51 origins (build-base has no upstream source). Each
  record in `MANIFEST.json` names its source and archive member and whether
  it is a whole member, the leading header lines of one, or a whole source
  file. The checker re-reads every one of the 236 records from its vendored
  source. `licenses/SPDX/` holds the
  SPDX license list index (`licenses.json`, `exceptions.json`) and the text
  of every listed identifier the closure's license fields name, from
  spdx/license-list-data v3.29.0.
- `attributions/<origin>.tsv`: for each of the 51 origins with upstream
  sources, the distinct copyright and attribution lines found anywhere in
  its upstream files and Alpine-local source files, each read to its end,
  with the method in
  `MANIFEST.json` (`attribution_method`). Each `line` row gives how often the
  line occurs, the first file it was seen in, and the line's exact bytes.
  Fields are escaped so that no field holds a tab, CR or LF and no row ends
  in a space:
  a backslash, tab, CR or LF is written `\\`, `\t`, `\r` or `\n`, and a byte
  that is not UTF-8, a byte of a control, a non-space separator, a Unicode
  15.1 format character (category Cf, which includes the bidirectional
  controls), a surrogate or a noncharacter (a fixed list in the checker,
  independent of the Python version), or a trailing space is written
  `\xNN`. `unescape_field` in the checker restores the
  original bytes; nothing is stripped, collapsed or shortened. Each
  `binary-head` row names a file the scan could not read as text, an
  `over-member-limit` row a file larger than the member limit, an
  `unscanned-member` row an archive member that holds data but is not a
  plain regular file (sparse, or of an unknown type), and a `long-lines`
  row a file with lines the scan could not record. The header counts files
  scanned, files with at least one line, and each of those four kinds of
  file.
- `MANIFEST.json` ties each archive's sha256 to its origin, aports commit,
  recipe files, sources, notices and attribution inventory. `SHA256SUMS`
  covers every other file.

The 20 origins marked `source_obligation` in `MANIFEST.json` (an archive
license names GPL, LGPL, AGPL, MPL or Artistic) are acl, attr, bash,
ca-certificates, coreutils, gcc, gdbm, git, libcap-ng, libidn2,
libunistring, linux-headers, lz4, make, patch, perl, perl-error, readline,
util-linux and xz. perl and perl-error are dual licensed with
Artistic-1.0-Perl; their source is included either way. The sources of the other 31 origins are vendored as well, so the
whole closure is one reviewable source unit.

## Cloning the complete unit

The APKs and upstream source payloads use Git LFS. Install Git LFS, then
hydrate the unit after cloning and before verifying, rebuilding or packaging:

```
git lfs pull --include='deploy/docker/security-evidence-apks/**,deploy/docker/security-evidence-apk-sources/**' --exclude=''
```

A Git archive or a checkout with LFS smudging disabled can contain pointers
instead of payloads. The checks reject those pointers. CI hydrates the
source unit before the source gate and contract self-tests, and hydrates
only the APK directory before building the trusted image.

## Finding the source of an archive

1. Look the archive's file name up in `MANIFEST.json` under
   `origins[].binaries`. Its origin record names the aports commit and
   version, which equal the `origin`, `commit` and `pkgver` fields of the
   `.PKGINFO` in the archive's control segment.
2. The recipe is `recipes/<origin>/`. The APKBUILD's `source=` lists the
   upstream files and the Alpine-local files; `sha512sums=` pins them.
3. The upstream files are in `sources/<origin>/` and the Alpine-local files
   in `recipes/<origin>/`.
   The URLs in `MANIFEST.json` record where each file was fetched from; they
   are provenance only, and nothing here depends on them staying online.

## Split archive

GitHub refuses files over 100 MiB, so `linux-6.14.tar.xz` (149,408,504
bytes) is stored as three chunks of at most 48 MiB next to
`sources/linux-headers/linux-6.14.tar.xz.chunks.json`, which records each
chunk's offset, length and digests and the whole archive's length, sha256 and
sha512. To rebuild it:

```
cd sources/linux-headers
cat linux-6.14.tar.xz.part-001 linux-6.14.tar.xz.part-002 linux-6.14.tar.xz.part-003 > /tmp/linux-6.14.tar.xz
sha512sum /tmp/linux-6.14.tar.xz
```

The digest must equal the `linux-6.14.tar.xz` line of
`recipes/linux-headers/APKBUILD`.

## Verifying

```
python3 scripts/check-security-apk-sources.py
(cd deploy/docker/security-evidence-apk-sources && sha256sum -c SHA256SUMS)
```

Required CI runs the checker and its self-test
(`scripts/tests/check-security-apk-sources.test.py`) in the
`APK corresponding source gate` step of `.github/workflows/ci.yml`.
`scripts/check-security-ci-contract.py` requires that step exactly and
unconditionally, requires the checker's manifest pin to be this
`MANIFEST.json`, and requires this manifest to name the archive manifest and
provenance that the security image installs from. It also pins the reviewed checker and self-test code digests. Changes to
either file require an explicit pin update and review. These pins alone do
not authenticate an author who can change both the code and its contract;
trusted definition/source authorization and qualification remain separate.

The checker reads local files only, through a descriptor of the repository
root that never follows a symlink below it. It:

- pins `MANIFEST.json` and requires the directory to match `SHA256SUMS`
  exactly;
- re-reads origin, commit, version and license from the `.PKGINFO` in each
  archive's control segment, refusing links, sparse entries, repeated names
  and oversized members. It checks only the shape of the signature segment
  (one member named for the pinned Alpine key) and does not verify the RSA
  signature; `apk add` does that during the image build;
- follows the retained aports commit and tree objects from each commit to
  its package directory and requires the recipe files to be exactly those
  blobs;
- reads each APKBUILD as text (it never runs one) for its version, license
  field and `sha512sums` block, checks every vendored source against that
  block, and checks the upstream URLs that its top-level `source=` names
  through plain parameter expansion (54 of 109). The other 55, mostly the
  bash and readline patch loops, are recorded as `not-expanded`: they are
  acquisition metadata, and their content is pinned by sha512 only;
- rebuilds the split archive in memory;
- requires every upstream source of every origin and abuild revision to be
  vendored here, re-reads every notice from its vendored source, and accepts
  an origin without notices only when it has no upstream source;
- re-derives, in the same pass over each vendored source, the attribution
  inventory of every origin and requires it byte for byte;
- splits license tokens into identifiers on the vendored SPDX list (each
  with its text) and unresolved tokens.

## Basis

Source access follows the GNU General Public License FAQ
(https://www.gnu.org/licenses/gpl-faq.en.html) and section 6 of GPLv3
(https://www.gnu.org/licenses/gpl-3.0.html):

- "I downloaded just the binary from the net. If I distribute copies, do I
  have to get the source and distribute that too?" (#UnchangedJustBinary):
  yes, redistributing unmodified binaries still requires the complete
  corresponding source.
- "Can I make binaries available on a network server, but send sources only
  to people who order them?" (#AnonFTPAndSendSources): the source must be
  on a network server as well, as easy to reach as the object code, and must
  correspond exactly to the binaries. GPLv3 section 6(d) describes this as
  equivalent access to the Corresponding Source in the same way through the
  same place. Here the source sits in the same repository and commit as the
  archives and is available through a hydrated Git LFS clone.
- "I want to distribute binaries, but distributing complete source is
  inconvenient. Is it ok if I give users the diffs from the 'standard'
  version along with the binaries?" (#DistributingSourceIsInconvenient):
  no; the complete sources are needed because the upstream site may not have
  the right version later. That is why the upstream archives are stored here
  rather than linked.
- GPLv3 section 1 counts the scripts used to control compilation and
  installation as part of the Corresponding Source; the APKBUILDs and the
  abuild revisions that ran them are included for that reason.
- "Does the GPL require me to provide source code that can be built to match
  the exact hash of the binary I am distributing?"
  (#MustSourceBuildToMatchExactHashOfBinary): no. This directory supplies the
  source the archives were built from; it does not claim that rebuilding it
  reproduces the archives' hashes.

No written offer is made or relied on.

## Scope and limits

This is an engineering distribution choice. It does not represent that a
license scan, Alpine's package metadata or this directory alone proves
compliance with any license, and it is not legal advice. Alpine's license
fields are package-level and coarse: upstream trees carry further licenses
(for example util-linux ships an EUPL-1.2 text and gcc the GCC Runtime
Library Exception), which is why the upstream license files are copied rather
than inferred.

Recorded gaps, also listed in `MANIFEST.json`:

- The attribution inventories are what one mechanical scan finds: every
  line, anywhere in a text file, that matches its copyright marker. Files
  that are not text are listed, not scanned (3,581 `binary-head` rows, for
  example compressed test data, images, nested archives and the
  xz-compressed kernel patch). The scan streams each file in 1 MiB blocks
  under fixed limits: a file over 64 MiB is listed as `over-member-limit`,
  and a line over 1 MiB is not recorded; when that line carries the marker
  anywhere (the part past 1 MiB is still searched), its file is listed under
  `long-lines`, whatever the read sizes. Each source is decompressed whole
  (every gzip member, xz stream or bzip2 stream). Between and after xz
  streams only stream padding (zero bytes, a multiple of four) is allowed,
  and after a bzip2 stream only another stream; after the tar archive ends
  the rest of the decompressed stream must be zero bytes. So neither a
  decoder nor a tar reader that stops early can hide a later member. A
  sparse or unknown-type member is listed under `unscanned-member`. The
  current closure has no `over-member-limit`, `unscanned-member` or
  `long-lines` rows. A source over 2 GiB, or more than 8 GiB streamed in
  all, fails the check rather than being cut short.
  Attribution that does not use the marker is not found. No person has
  reviewed the lines, and nothing here is a legal-compliance finding.

- build-base has no upstream source (it is a metapackage). It records
  `notices_absent: no-upstream-source`, which the checker accepts only for
  an origin with no upstream source; no free-text reason is accepted.
- The ca-certificates archive ships no separate license file. Its notices
  are the leading header lines of `certdata.txt` (MPL-2.0), `c_rehash.c`
  (MIT) and `mk-ca-bundle.pl` (curl), copied from the vendored archive and
  checked against it.
- Alpine's license fields contain two tokens that are not on the SPDX
  license list: `LGPL-1.0-only` (the util-linux `blkid` subpackage) and
  `Public-Domain` (libarchive, util-linux, xz). `MANIFEST.json` keeps every
  license field exactly as Alpine wrote it, lists these tokens under
  `unrecognized_license_tokens` with status `unresolved`, and infers nothing
  from them, including nothing about notices or attribution.

## Updating

Any change to `../security-evidence-apks/SHA256SUMS` or
`../security-evidence-apk-archives.json` changes the digests `MANIFEST.json`
records, so the checker fails until this directory is regenerated for the
new closure and the manifest pin in `scripts/check-security-apk-sources.py`
is updated in the same change.
