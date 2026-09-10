# bash completion for nkgrep — static flag list, mirrors `nkgrep --help`
# Install: copy to /etc/bash_completion.d/ or source from ~/.bashrc:
#   source /path/to/nkgrep.bash
_nkgrep() {
    local cur prev words cword
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]:-}"

    local opts="-i --ignore-case -q --quiet --silent -v --invert-match -w --word-regexp -F --fixed-strings -m --max-count -e --regexp -f --file -c --count -l --files-with-matches --format --color -. --hidden --no-ignore -L --follow -g --glob -d --max-depth --max-filesize -A --after-context -B --before-context -C --context --group-separator --top --use-index --port --index --help -h --version -V -- -"

    case "$prev" in
        --top|--port|-m|--max-count|-d|--max-depth|--max-filesize)
            # numeric argument: nothing to complete
            return 0
            ;;
        -A|--after-context|-B|--before-context|-C|--context)
            # numeric argument: nothing to complete
            return 0
            ;;
        --format)
            COMPREPLY=($(compgen -W "json text" -- "$cur"))
            return 0
            ;;
        --color)
            COMPREPLY=($(compgen -W "auto always never ansi" -- "$cur"))
            return 0
            ;;
        --group-separator|-g|--glob)
            # free-text argument: nothing to complete
            return 0
            ;;
        --use-index|--index|-f|--file)
            COMPREPLY=($(compgen -f -- "$cur"))
            return 0
            ;;
        -e|--regexp)
            # free-text pattern: nothing to complete
            return 0
            ;;
    esac

    # First positional: subcommands
    local i word
    local seen_sub=""
    for ((i = 1; i < COMP_CWORD; i++)); do
        word="${COMP_WORDS[i]}"
        case "$word" in
            -*|--top|--use-index|--port|--index|-m|--max-count|-e|--regexp|-f|--file) ;;
            *) ;;
        esac
    done

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
        return 0
    fi

    if [[ -z "$seen_sub" ]]; then
        COMPREPLY=($(compgen -W "index serve $opts" -- "$cur"))
        return 0
    fi

    case "$seen_sub" in
        index|serve)
            COMPREPLY=($(compgen -f -- "$cur"))
            return 0
            ;;
    esac
}

complete -F _nkgrep nkgrep
