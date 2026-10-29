# Gift Exchange

A tiny static site: people type their name and see who they're giving a gift to. Nobody can see anyone else's pairing.

## Files

| File | Purpose |
|---|---|
| `index.html` | The page your group uses |
| `core.js` | Shared logic (pairing rules + encryption) |
| `data.json` | The encrypted draw (placeholder until you generate one) |
| `admin.html` | Organiser tool that creates `data.json` (open it on your computer) |

## Setup (about 5 minutes)

1. **Generate the draw.** Double-click `admin.html` (it works locally, no server needed).
   Paste the names (one per line), optionally tick *personal codes*, click **Generate draw**, then **Download data.json**.
2. **Create a GitHub repository** and upload `index.html`, `core.js` and the new `data.json`.
   (`admin.html` can stay on your computer; it's harmless if you upload it too.)
3. **Turn on GitHub Pages:** repo → *Settings* → *Pages* → Source: *Deploy from a branch* → `main` / `(root)` → Save.
4. Share the link `https://<your-username>.github.io/<repo-name>/` with the group.
   If you used personal codes, send each person their own code privately.

## Rules the draw follows

- Nobody is paired with themselves.
- Everyone gives exactly one gift and receives exactly one.
- People who share any name word (e.g. both have "Isaac") are never paired together. Single-letter initials are ignored.
- To override, add a family tag: `Odumusi Olamide | Odumusi`. When a tag is present, only the tag is used for that person.

## Privacy

`data.json` contains only encrypted results (AES-GCM, key derived from the person's name, plus their personal code if enabled).
Without personal codes, someone who knows another person's exact name could look them up, so use codes if that matters.
The organiser tool never shows the pairings.
