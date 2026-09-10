# fish completion for nkgrep — static flag list, mirrors `nkgrep --help`
# Install: copy to ~/.config/fish/completions/nkgrep.fish

# Subcommands
complete -c nkgrep -f -n '__fish_use_subcommand' -a index -d 'build trigram index'
complete -c nkgrep -f -n '__fish_use_subcommand' -a serve -d 'serve index as daemon'

# Search flags
complete -c nkgrep -s i -l ignore-case -d 'case-insensitive match'
complete -c nkgrep -s q -l quiet -d 'suppress stdout, stop at first match'
complete -c nkgrep -l silent -d 'alias for --quiet'
complete -c nkgrep -s c -l count -d 'path:count per matching file'
complete -c nkgrep -s l -l files-with-matches -d 'matching paths only'
complete -c nkgrep -s v -l invert-match -d 'print non-matching lines'
complete -c nkgrep -s w -l word-regexp -d 'match whole words only'
complete -c nkgrep -s F -l fixed-strings -d 'patterns are literal strings'
complete -c nkgrep -s m -l max-count -d 'max matches per file' -x
complete -c nkgrep -s e -l regexp -d 'search pattern (repeatable)' -x
complete -c nkgrep -s f -l file -d 'pattern file (repeatable)' -r -F
complete -c nkgrep -l format -d 'output rendering (json|text)' -x -a 'json text'
complete -c nkgrep -l color -d 'highlight match spans' -x -a 'auto always never ansi'
complete -c nkgrep -s . -l hidden -d 'search hidden files'
complete -c nkgrep -l no-ignore -d 'skip ignore files'
complete -c nkgrep -s L -l follow -d 'follow symbolic links'
complete -c nkgrep -s g -l glob -d 'include/exclude glob (repeatable)' -x
complete -c nkgrep -s d -l max-depth -d 'limit traversal depth' -x
complete -c nkgrep -l max-filesize -d 'skip files larger than N bytes' -x
complete -c nkgrep -s A -l after-context -d 'lines after each match' -x
complete -c nkgrep -s B -l before-context -d 'lines before each match' -x
complete -c nkgrep -s C -l context -d 'lines around each match' -x
complete -c nkgrep -l group-separator -d 'context group separator' -x
complete -c nkgrep -l top -d 'top N ranked matches' -x
complete -c nkgrep -l use-index -d 'index file' -r -F
complete -c nkgrep -l port -d 'daemon port' -x
complete -c nkgrep -l index -d 'index file' -r -F
complete -c nkgrep -s h -l help -d 'print help'
complete -c nkgrep -s V -l version -d 'print version'
