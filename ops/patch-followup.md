# Authorized patch follow-up

`patch-followup` finishes a finite owner-approved review of previously selected
commit patches. It is separate from default discovery and observation. Use it
only after the owner explicitly authorizes continued inspection of sensitive
candidates and, when requested, authenticated GitHub commit metadata.

Copy [the example manifest](../examples/patch-followup.example.json) into ignored
private storage. Replace the case ID, authorization reference, expiry, and exact
patch `asset_refs` using that case's locator store. The bound repositories must
have confirmed ownership and current authorization. Both the manifest and the
network scope must be unexpired. A local authorization reference records the
operator's declaration; it is not a cryptographic approval signature.

```sh
open-detective patch-followup --case _local/case --scope _local/scope.json --manifest _local/followup.json --output _local/followup-result.json
```

For approved GitHub login use, provide only an environment variable **name** with
`--token-env OPEN_DETECTIVE_METADATA_TOKEN`. Obtain its value through the owner's
credential manager without printing it or storing it in the manifest. The token
is confined to exact commit-detail API requests for the selected repositories.
Patch and raw-file requests use the anonymous scoped transport, without that
token, cookies, or a browser session. Authenticated metadata never proves that
the content is publicly accessible.
Without the authorized metadata credential, the run records a metadata gap;
the anonymous patch capture alone does not complete the before/after review.

The review validates commit SHA, parent and file metadata and follows validated
pagination within fixed limits. It inspects the patch and the corresponding
current and first-parent file revisions, including removed and renamed files.
Unavailable or binary patches can still receive full-file analysis. Those file
captures are not represented as reconstructed patch hunks. Merge-parent and
unsupported-format limitations remain visible.
When a patch returns HTTP 503 without a provider retry delay, the exact same
commit's public `.diff` may be measured separately. A successful diff does not
change the failed patch observation. Provider retry delays are respected.
Unsupported binary formats remain unprocessed instead of being treated as
clean text.

Sensitive candidates no longer stop this explicitly approved review at the
first match. Candidate output distinguishes source literals, populated
structured values, field labels, example markers, and format matches without
returning the values. A phone or plate format does not establish a person's
identity or publication approval. A password literal is not tested against a
service. Image OCR resumes by image index within explicit byte, pixel, and time
limits; image data is excluded from text classification to avoid base64 false
positives. OCR is not a complete visual inspection.

Append-only follow-up evidence is kept in the existing private case ledger,
linked to the authorization and exact asset. Original measurements and their
failures remain unchanged. Resume with the same manifest and a new output path;
completed work is reused and unresolved processing stays eligible within the
authorized attempt and budget limits. A changed scope or authorization must be
explicit, not an automatic retry side effect.

`processing_complete` describes execution of the supported bounded analyses.
`overall_verified` and the pending review dimensions describe the stronger
verification claim. Neither closes an exposure, approves publication, proves
no data loss, or establishes company-wide coverage. Inspect the actual results
and report both counts. Keep company inputs, raw locations and reports private;
never commit credentials or source captures.
