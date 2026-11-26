#!/usr/bin/env zsh
set -eu

bash --noprofile --norc -s "${0:A:h}/../src/hooks/completions/bash.sh" <<'BASH'
set -eu
source "$1"
omg() {
    case "$5" in
        frfx) printf '%s\n' firefox ;;
        gt) printf '%s\n' git ;;
        failure) printf '%s\n' firefox; return 1 ;;
    esac
}
for query in frfx gt unmatched failure; do
    COMP_WORDS=(omg install "$query")
    COMP_CWORD=2
    COMP_LINE="omg install $query"
    _omg_completions
    printf 'Bash %s => %s\n' "$query" "${COMPREPLY[*]-}"
    case "$query" in
        frfx) [[ "${COMPREPLY[*]}" == firefox ]] ;;
        gt) [[ "${COMPREPLY[*]}" == git ]] ;;
        *) [[ ${#COMPREPLY[@]} -eq 0 ]] ;;
    esac
done
BASH

fish --no-config -c '
    source "$argv[1]"
    function omg
        switch "$argv[9]"
            case "omg install ba" "omg --quiet install git ba" "omg remove glibc ba"
                printf "%s\n" bash.x86_64
            case "omg use node 22."
                printf "%s\n" 22.14.0
            case "omg sy no"
                printf "%s\n" node
            case "omg install fa"
                printf "%s\n" failed-package
                return 1
        end
    end
    for line in "omg install ba" "omg --quiet install git ba" "omg remove glibc ba"
        set -l suggestions (complete -C "$line")
        contains -- bash.x86_64 $suggestions
        or begin
            printf "Fish missed package completion in %s\n" "$line" >&2
            exit 1
        end
    end
    set -l suggestions (complete -C "omg use node 22.")
    contains -- 22.14.0 $suggestions
    or begin
        printf "Fish missed the runtime version completion\n" >&2
        exit 1
    end
    set -l suggestions (complete -C "omg sy no")
    contains -- node $suggestions
    set -l suggestions (complete -C "omg install fa")
    if contains -- failed-package $suggestions
        printf "Fish accepted partial output from a failing completion\n" >&2
        exit 1
    end
' "${0:A:h}/../src/hooks/completions/fish.fish"

zmodload zsh/zpty
zmodload zsh/system
zmodload zsh/datetime
print -r -- 'phase: zpty module loaded'
owner=$sysparams[pid]
cache_root=${XDG_CACHE_HOME:-$HOME/.cache}
mkdir -p "$cache_root"
fixture=$(mktemp -d "$cache_root/omg-zsh-completion.XXXXXXXX")
cleanup() {
    [[ $sysparams[pid] == $owner ]] || return 0
    if zpty -t child 2>/dev/null; then
        zpty -d child
    fi
    rm -rf -- "$fixture"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
print -r -- 'phase: fixture ready'
typeset -F deadline=$(( EPOCHREALTIME + 15 ))
read_until() {
    local LC_ALL=C
    local pattern=$1 phase=$2 chunk buffer=''
    while (( EPOCHREALTIME < deadline )); do
        if zpty -r child chunk; then
            buffer+=$chunk
            if (( ${#buffer} > 1048576 )); then
                print -r -u2 -- "Completion output exceeded 1048576 bytes while waiting for $phase"
                return 1
            fi
            if [[ "$buffer" == ${~pattern} ]]; then
                output=$buffer
                return 0
            fi
        fi
        if ! zpty -t child; then
            print -r -u2 -- "Completion child exited while waiting for $phase"
            print -r -u2 -- "$buffer"
            return 1
        fi
        sleep 0.01
    done
    print -r -u2 -- "Completion deadline exceeded while waiting for $phase"
    print -r -u2 -- "$buffer"
    return 1
}
mkdir "$fixture/fpath"
cp "${0:A:h}/../src/hooks/completions/zsh.zsh" "$fixture/fpath/_omg"
child_log=/tmp/omg-zsh-child.log
: > "$child_log"
cat > "$fixture/.zshrc" <<'RC'
print -r -- 'child: zshrc start' >> /tmp/omg-zsh-child.log
fpath=("$ZDOTDIR/fpath" $fpath)
autoload -Uz compinit
compinit -i -D
print -r -- 'child: compinit done' >> /tmp/omg-zsh-child.log
PROMPT='READY> '
omg() {
    print -r -- "$5" >> "$ZDOTDIR/completion-calls"
    case "$5" in
        frfx) print -r -- firefox ;;
        gt) print -r -- git ;;
        failure) print -r -- firefox; return 1 ;;
    esac
}
capture_buffer() {
    print -r -- "CAPTURE:$BUFFER:END"
    zle redisplay
}
zle -N capture_buffer
bindkey '^X' capture_buffer
RC
export ZDOTDIR=$fixture TERM=xterm
zpty -b child zsh -d -i
print -r -- 'phase: zpty spawned, waiting for prompt'
read_until '*READY>*' 'ready prompt'
print -r -- 'phase: prompt ready'
zpty -w -n child $'omg install frfx\t\C-x'
print -r -- 'phase: typed frfx'
read_until '*CAPTURE:*:END*' 'frfx capture'
print -r -- 'phase: captured frfx'
print -r -- "$output"
[[ "$output" == *'CAPTURE:omg install firefox :END'* ]]
zpty -w -n child $'\C-a\C-komg install gt\t\C-x'
print -r -- 'phase: typed gt'
read_until '*CAPTURE:*:END*' 'gt capture'
print -r -- 'phase: captured gt'
print -r -- "$output"
[[ "$output" == *'CAPTURE:omg install git :END'* ]]
zpty -w -n child $'\C-a\C-komg install zzzz-unmatched\t\C-x'
print -r -- 'phase: typed unmatched'
read_until '*CAPTURE:*:END*' 'unmatched capture'
print -r -- 'phase: captured unmatched'
print -r -- "$output"
[[ "$output" == *'CAPTURE:omg install zzzz-unmatched:END'* ]]
[[ $(grep -c '^zzzz-unmatched$' "$fixture/completion-calls") == 1 ]] || {
    print -r -u2 -- 'Zsh requested suggestions more than once for an unmatched token'
    exit 1
}
zpty -w -n child $'\C-a\C-komg install failure\t\C-x'
read_until '*CAPTURE:*:END*' 'failed suggestion capture'
[[ "$output" == *'CAPTURE:omg install failure:END'* ]]
[[ $(grep -c '^failure$' "$fixture/completion-calls") == 1 ]]
print -r -- 'phase: all captures verified'
