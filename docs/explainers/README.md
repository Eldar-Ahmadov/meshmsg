# Mesh notes: interactive explainers

Open **index.html** in a browser. It shows a thumbnail for each concept, and each thumbnail links to that concept's full interactive page. The pages are static and self-contained, with no server and no network requests.

| Page | Concept |
| --- | --- |
| `gossip.html` | Gossip propagation: fanout, duplicate copies, peers going offline, and splitting the network |
| `file-sharing.html` | File sharing: pinning before announcing, signed offers sent by gossip, explicit downloads, verified 16 KiB blocks, and installs that never overwrite |

Each page has breadcrumbs back to the index and previous/next links. The theme toggle is remembered across pages (`localStorage`), and `?theme=light` or `?theme=dark` forces a theme.

Both models are simplified and are not protocol traces. Each page's footer says what it leaves out. The file-sharing page follows the order of checks in `src/attachment/transfer.rs` and the constants in `docs/contracts.md`.

## Layout

```
build.mjs          builds index.html, gossip.html and file-sharing.html
site.css           index cards, breadcrumbs, pager and shared overrides
vendor/iso-kit.mjs snapshot of the anatomy skill's SVG kit
gossip/            model.mjs, live.js, build.mjs (exports the concept), style.css (shared base styles), tests and checks
file-sharing/      model.mjs, live.js, build.mjs (exports the concept), style.css, tests and checks
```

To add a concept, give it a folder whose `build.mjs` exports `concept = { slug, num, kicker, title, pageTitle, summary, cta, svg, thumb, body, css, script }`, with `__NAV__` at the top of `body`. Then add it to `CONCEPTS` in `build.mjs`.

## Build and test

```sh
node docs/explainers/build.mjs
node --test docs/explainers/gossip/model.test.mjs docs/explainers/file-sharing/model.test.mjs

S=.pi/skills/anatomy/scripts   # browser checks need the anatomy skill and Chromium
node $S/drive.mjs docs/explainers/gossip.html --actions docs/explainers/gossip/browser-checks.json --reduced --height 2000
node $S/drive.mjs docs/explainers/gossip.html --actions docs/explainers/gossip/motion-checks.json --height 2000
node $S/drive.mjs docs/explainers/file-sharing.html --actions docs/explainers/file-sharing/browser-checks.json --reduced --height 2000
node $S/lines.mjs "file://$PWD/docs/explainers/file-sharing.html?theme=light" --reduced
```
