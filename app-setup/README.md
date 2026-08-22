# GitHub App setup helper

A single static page ([`index.html`](index.html)) that walks through
creating the GitHub App recommended in the
[main README](../README.md#creating-the-recommended-github-app) using
GitHub's own
[app manifest flow](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest).

## What it actually does (read this before you trust it with a private key)

1. You fill in an org/user login, App name, and homepage URL. The page
   builds a GitHub App
   [manifest](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest#github-app-manifest-parameters)
   requesting exactly one permission: organization **Members: Read-only**,
   no webhook, no OAuth login.
2. Your browser POSTs that manifest directly to
   `https://github.com/organizations/<owner>/settings/apps/new` (or
   `https://github.com/settings/apps/new` for a personal account) — GitHub's
   own page, not this one. You review and confirm there.
3. GitHub redirects back to this page with a one-time `?code=...`.
4. This page's JavaScript exchanges that code for the App's credentials by
   calling `POST https://api.github.com/app-manifests/<code>/conversions`
   **directly from your browser**. That endpoint needs no authentication —
   the code itself is the one-time credential, and it expires quickly.
5. The response (App ID, slug, and private key) is rendered in the page and
   offered as a `.pem` download. It is held only in this page's in-memory
   JavaScript state — never written to `localStorage`, a cookie, or any
   server.

There is no backend anywhere in this flow. That's not a design choice made
for cost reasons — it's the property that makes it safe to host this
statically and safe for you to run entirely from a local file if you'd
rather not use a hosted copy at all.

## Running it

Three equivalent options, in increasing order of "don't have to trust
anyone's hosting":

- **Hosted copy** (if published — see [Hosting](#hosting) below): open the
  URL, use it like any web page.
- **Locally, no server**: download `index.html` and open it directly in a
  browser (`file://`). The manifest POST and the code-exchange `fetch` both
  work over `file://` because they don't depend on this page's own origin
  for anything except constructing `redirect_url`.
- **Locally, with a server** (only needed if you want a nicer URL than
  `file://`): `python3 -m http.server --directory app-setup 8000`, then
  open `http://localhost:8000`.

## Hosting

This folder is deployed to GitHub Pages by
[`.github/workflows/deploy-app-setup-pages.yml`](../.github/workflows/deploy-app-setup-pages.yml)
using the standard `actions/configure-pages` + `actions/upload-pages-artifact`
+ `actions/deploy-pages` flow. One manual, one-time step is required before
that workflow's deployment actually takes effect:

> Repository **Settings → Pages → Build and deployment → Source**, select
> **GitHub Actions**.

**Why GitHub Pages and not Cloudflare Pages/Workers:** this page needs no
server-side logic at all (see above) — the manifest-conversion endpoint is
public and unauthenticated by design, so there is nothing for a Worker to
do that the browser can't already do directly. GitHub Pages keeps the setup
helper in the same repository and trust boundary as the Action it configures,
with no separate hosting account, DNS, or deployment target to manage. If you
already run Cloudflare Pages for other static sites in your org, this folder
is plain static HTML/CSS/JS and will work there identically — just point it
at `app-setup/` as the build output directory.

## Customizing

- The default permission requested is `members: read` (the only one this
  action's core authorization checks need). Add more under
  `default_permissions` in `index.html`'s manifest object if your org wants
  this same App to also cover other automation — keep in mind that widens
  what a leaked App private key can do.
- The App name field defaults to `workflow-gatekeeper-authorizer`; change it
  to match your org's naming convention before sharing this page internally.
