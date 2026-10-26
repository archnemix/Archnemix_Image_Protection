# A plain-language guide for image owners

This guide explains what Archx does for photographers, agencies, stock
libraries, and other image owners without assuming software knowledge. It is
not legal advice.

## The short version

Archx makes casual downloading and bulk copying much harder. It does not
make a displayed picture impossible to copy.

With the recommended server setup, your website never sends the original
master file to a visitor. It sends a limited-size viewing copy through a
temporary permission check. That viewing copy can carry visible and hidden
marks that help you investigate a leak later.

A determined person can still screenshot or photograph what is on their
screen. Archx reduces the value and convenience of that copy and improves
your evidence; it cannot repeal the "analog hole."

## What Archx prevents or makes harder

- **Ordinary right-click saving:** the protected viewer does not present the
  valuable image as a normal downloadable image file.
- **Guessing the original file address:** masters stay outside the public
  website folder and the protected route only returns an approved viewing
  derivative.
- **Sharing a temporary viewing link:** links/tokens expire quickly, can be
  one-time, and can require the same browser proof key that requested them.
- **Asking for a larger file than the account allows:** your server sets the
  maximum width/quality for each viewer. The browser cannot simply request
  the master size.
- **Bulk scraping:** sign-in/entitlement checks, rate limits, per-viewer and
  per-image quotas, and unusual-download alerts make mass collection slower
  and more visible.
- **Anonymous reposting:** visible watermarks, forensic marks, and optional
  StegoMark fingerprints can connect a suspect copy to an image, viewer,
  order, or campaign if you save the issuance records.

## What Archx cannot promise

- It cannot stop screenshots, screen recording, a second phone camera, or a
  privileged browser tool from capturing displayed pixels.
- It cannot stop an authorized expert from reconstructing the viewing-size
  copy they were allowed to see.
- It cannot guarantee that a hidden mark survives heavy cropping, rotation,
  perspective photography, filtering, or AI regeneration. The measured
  limits are in the technical documentation.
- It cannot decide copyright ownership or infringement. A fingerprint match
  is evidence to investigate, not a court ruling by itself.
- Client-only protection cannot rescue an original that is also available at
  a public URL somewhere else.

## Recommended settings by use case

### Photographer portfolio

- Publish small public thumbnails normally for search and sharing.
- Protect large portfolio views through the token server.
- Keep print-resolution masters offline or in private storage.
- Use a tasteful visible watermark on proofs and a hidden StegoMark where
  attribution matters.
- Set the public derivative only as large as the designed page needs.

### Stock-photo previews

- Require an account or an explicit preview entitlement for large comps.
- Use short-lived one-time tokens, per-account quotas, distinct-image alerts,
  and server-baked watermarks.
- Save every StegoMark issuance against image, account, license inquiry, and
  time.
- Deliver purchased masters through your normal licensed-download system,
  not through the public preview route.

### Paid galleries and client proofs

- Authorize every image against the current customer/order at both request
  and delivery time; a cancelled order should stop working immediately.
- Give each customer only the size and quality included in their plan.
- Use proof-of-possession mode when your supported browsers allow it.
- Disable query-string tokens so access secrets do not appear in URLs/logs.
- Keep an audit trail of which account viewed which image and when, subject
  to your privacy policy.

## If you find a suspected copy

1. Save the suspect file exactly as found. Do not edit, resize, or re-save
   the evidence copy.
2. Record where and when you found it, the URL/account, screenshots of the
   surrounding page, and any license/order details.
3. Preserve the original master, RAW files, invoices, model/property
   releases, publication history, and your issuance registry.
4. Run `archx-detect` or ask your developer to run the StegoMark and
   perceptual-fingerprint checks. Record the tool version and settings.
5. Compare the recovered fingerprint with your registry. A match identifies
   a candidate issuance; corroborate it with account/order and server logs.
6. Ask qualified legal counsel about takedown, licensing, or enforcement in
   the relevant country/platform. Platform reporting processes and copyright
   rules vary.

## Questions to ask a vendor or developer

- Are the masters outside the public web folder, and can you show that the
  direct master URL returns "not found"?
- Is access checked when the image is requested and again when delivered?
- If there is more than one server, do all servers share the one-time-token
  and quota records?
- How are signing secrets generated, rotated, and retired?
- Does the CDN bypass shared caching for protected token/image routes? Has
  a replay test through the public CDN hostname passed?
- Are StegoMark fingerprints saved with customer/order records and the key
  ID needed to investigate them later?
- Are security events sent somewhere that a person actually monitors?
- Has the complete production deployment—not just the library—been tested
  with revoked users, another customer's image ID, quota exhaustion, and a
  state-store outage?
- What happens during server failover: does it safely pause, or could an old
  viewing token be used twice?
- Which browsers and phones were actually tested with the selected viewer
  settings?

## A realistic protection promise

A fair customer-facing claim is:

> "We deliver only limited-size, marked viewing copies through expiring,
> account-checked requests. This blocks ordinary downloading and makes bulk
> misuse slower, more visible, and easier to trace. No web technology can
> prevent every screenshot or photograph of a screen, so licensing terms,
> monitoring, and enforcement remain part of the protection."

Avoid claims such as "screenshot-proof," "unstealable," "DRM for images," or
"guaranteed ownership proof." Those claims are not technically supportable
for still images displayed in a normal web browser.
