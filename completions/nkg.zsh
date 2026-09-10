#compdef nkg
# zsh completion for nkg — static flag list, mirrors `nkg --help`
# Install: copy to a directory in $fpath (e.g. ~/.zsh/completions/_nkg)

_nkg() {
    local context state line
    typeset -A opt_args

    _arguments -C \
        '(-h --help)'{-h,--help}'[print help]' \
        '(-V --version)'{-V,--version}'[print version]' \
        '(-i --ignore-case)'{-i,--ignore-case}'[case-insensitive match]' \
        '(-q --quiet)'{-q,--quiet}'[suppress stdout, stop at first match]' \
        '--silent[alias for --quiet]' \
        '(-c --count)'{-c,--count}'[path:count per matching file]' \
        '(-l --files-with-matches)'{-l,--files-with-matches}'[matching paths only]' \
        '(-v --invert-match)'{-v,--invert-match}'[print non-matching lines]' \
        '(-w --word-regexp)'{-w,--word-regexp}'[match whole words only]' \
        '(-F --fixed-strings)'{-F,--fixed-strings}'[patterns are literal strings]' \
        '*{-m,--max-count=}+[max matches per file]:NUM:' \
        '*{-e,--regexp=}+[search pattern]:pattern:' \
        '*{-f,--file=}+[pattern file]:pattern file:_files' \
        '--format=[output rendering]:format:(json text)' \
        '--color=[highlight match spans]:when:(auto always never ansi)' \
        '(-. --hidden)'{-.,--hidden}'[search hidden files]' \
        '--no-ignore[skip ignore files]' \
        '(-L --follow)'{-L,--follow}'[follow symbolic links]' \
        '*{-g,--glob=}+[include/exclude glob]:glob:' \
        '*{-d,--max-depth=}+[limit traversal depth]:N:' \
        '--max-filesize=[skip large files]:bytes:' \
        '*{-A,--after-context=}+[lines after match]:N:' \
        '*{-B,--before-context=}+[lines before match]:N:' \
        '*{-C,--context=}+[lines around match]:N:' \
        '--group-separator=[context group separator]:separator:' \
        '--top+[top N ranked matches]:N:' \
        '--use-index+[index file]:index file:_files' \
        '--port+[daemon port]:port:' \
        '--index+[index file]:index file:_files' \
        '--[end of flags]' \
        '-:stdin operand:( - )' \
        '1:subcommand:(index serve)' \
        '*:: :->args' && return 0

    case "$state" in
        args)
            case "${line[1]}" in
                index)
                    _arguments \
                        '--index+[index file]:index file:_files' \
                        '1:root:_files -/' && return 0
                    ;;
                serve)
                    _arguments \
                        '--index+[index file]:index file:_files' \
                        '--port+[daemon port]:port:' && return 0
                    ;;
            esac
            ;;
    esac

    return 1
}

_nkg "$@"
