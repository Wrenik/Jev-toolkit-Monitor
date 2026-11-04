# Author name: to be decided by the owner

The author name is not guessed. Every place that carries it holds the single placeholder
`AUTHOR_NAME_TODO`. Replace it in this repository, in these places:

- `LICENSE` (copyright line)
- `pyproject.toml` (`authors`)
- `.claude-plugin/marketplace.json` (`owner.name`)
- `claude-mod/jev-monitor/.claude-plugin/plugin.json` (`author.name`)

Find them all with: `git grep AUTHOR_NAME_TODO`. The same placeholder is used in the other five Jev-toolkit repositories;
change all six together so the marketplace owner, package metadata and licence agree.
