# Submission package for draft-whelan-chio-protocol-00

Prepared October 2, 2026 for publication with the completed security-roadmap release. This is an individual Internet-Draft with intended status Standards Track. The document does not claim working-group adoption. No mailing-list affiliation is assigned by this package.

The source is `draft-whelan-chio-protocol.md`. The upload file is `draft-whelan-chio-protocol-00.xml`, the expanded RFCXML v3 rendering. The prepped XML is the docs reader's source; text and PDF are companion renderings. [CLAIMS.md](CLAIMS.md) links the comprehensive review and its release acceptance contract.

Author: Connor Whelan, Backbay Industries, `connor@backbay.io`. Public source and issues: <https://github.com/backbay-labs/chio>.

## Release and submission steps

1. Reconcile the completed release with the review's explicit [implementation acceptance items](reviews/2026-10-02/README.md#changes-that-require-release-reconciliation). Preserve the source, build, wire, and operational evidence separately.
2. Review the source and rendered PDF. Set `date` to the actual submission date and regenerate all outputs. Confirm the draft name and revision against any preceding submission before reusing `-00`.
3. Publish the approved source revision to the public Chio repository. Verify that the website's source link resolves there, then regenerate the reader, downloads, search data, citations, and expiry from that public revision. The owner has authorized app shipment independently of the later Datatracker upload; there is no inherited site-after-upload gate.
4. When the owner proceeds with submission, upload the expanded XML at <https://datatracker.ietf.org/submit/>. Confirm name, revision, title, author email, IETF stream, intended status, date, and expiry. Complete the BCP 78/79 declarations and author confirmation.
5. After posting, compare the Datatracker rendering and official anchors with the site and downloads. Record the posted revision and URLs. Do not infer working-group adoption from an individual submission.

## Intellectual property answer

The owner answered the question about known patents or patent applications held by the owner, Backbay Industries, or another party: **"None that I am aware of."** Preserve that answer for the author's submission declarations. Any required disclosure is made at <https://datatracker.ietf.org/ipr/>.

## Timing

The internal posting target is November 1. Recheck the [IETF 127 important dates](https://datatracker.ietf.org/meeting/127/important-dates/) when scheduling the actual upload; this document's preparation date is not a submission timestamp.

## Regeneration and validation

Use kramdown-rfc 1.7.43, xml2rfc 3.34.1, WeasyPrint 70.0, aasvg 0.5.7, idnits 3.1.0, Python 3, Fontconfig, and `pdftotext`. The workflow installs the matching tool versions and native dependencies. The bundled OFL fonts and isolated `FONTCONFIG_FILE` pin PDF rendering. Put the Ruby gem's executable directory on PATH, or supply `KRAMDOWN=/path/to/kramdown-rfc`.

```sh
make -C spec/ietf
make -C spec/ietf check
```

The check verifies generated examples and folded bytes, compares fresh XML/prepped XML/text and extracted PDF text, rejects writer warnings, enforces 72-column text, and rejects idnits errors or warnings. The review additionally checks the selected roadmap source's protocol fixtures and signing-input separation; its reproducible command is in [verification.md](reviews/2026-10-02/verification.md).
