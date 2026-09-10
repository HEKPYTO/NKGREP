# fish completion for nkg — static flag list, mirrors `nkg --help`
# Install: copy to ~/.config/fish/completions/nkg.fish

# Subcommands
complete -c nkg -f -n '__fish_use_subcommand' -a index -d 'build trigram index'
complete -c nkg -f -n '__fish_use_subcommand' -a serve -d 'serve index as daemon'

# Search flags
complete -c nkg -s i -l ignore-case -d 'case-insensitive match'
complete -c nkg -s q -l quiet -d 'suppress stdout, stop at first match'
complete -c nkg -l silent -d 'alias for --quiet'
complete -c nkg -s c -l count -d 'path:count per matching file'
complete -c nkg -s l -l files-with-matches -d 'matching paths only'
complete -c nkg -s v -l invert-match -d 'print non-matching lines'
complete -c nkg -s w -l word-regexp -d 'match whole words only'
complete -c nkg -s F -l fixed-strings -d 'patterns are literal strings'
complete -c nkg -s m -l max-count -d 'max matches per file' -x
complete -c nkg -s e -l regexp -d 'search pattern (repeatable)' -x
complete -c nkg -s f -l file -d 'pattern file (repeatable)' -r -F
complete -c nkg -l format -d 'output rendering (json|text)' -x -a 'json text'
complete -c nkg -l color -d 'highlight match spans' -x -a 'auto always never ansi'
complete -c nkg -s . -l hidden -d 'search hidden files'
complete -c nkg -l no-ignore -d 'skip ignore files'
complete -c nkg -s L -l follow -d 'follow symbolic links'
complete -c nkg -s g -l glob -d 'include/exclude glob (repeatable)' -x
complete -c nkg -s d -l max-depth -d 'limit traversal depth' -x
complete -c nkg -l max-filesize -d 'skip files larger than N bytes' -x
complete -c nkg -s A -l after-context -d 'lines after each match' -x
complete -c nkg -s B -l before-context -d 'lines before each match' -x
complete -c nkg -s C -l context -d 'lines around each match' -x
complete -c nkg -l group-separator -d 'context group separator' -x
complete -c nkg -l top -d 'top N ranked matches' -x
complete -c nkg -l use-index -d 'index file' -r -F
complete -c nkg -l port -d 'daemon port' -x
complete -c nkg -l index -d 'index file' -r -F
complete -c nkg -s h -l help -d 'print help'
complete -c nkg -s V -l version -d 'print version'
