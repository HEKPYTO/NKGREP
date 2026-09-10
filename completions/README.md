# completions

Static completions for `nkg`, derived from `nkg --help`. When flags
change, update all three plus the man page.

## Install

bash (`~/.bashrc`):

```bash
source /path/to/completions/nkg.bash
```

zsh (`~/.zshrc`, after `compinit`):

```bash
fpath=(/path/to/completions $fpath)
```

fish:

```bash
cp completions/nkg.fish ~/.config/fish/completions/
```
