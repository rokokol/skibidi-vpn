# Tab completion for node names, sourced from the same registry the roles read.
#
#   source completion/skibidi-vpn.bash
#
# Works in zsh too, after `autoload -U bashcompinit && bashcompinit`.
_skibidi_nodes() {
    local dir="${SKIBIDI_NODES_DIR:-inventory/nodes}"
    [[ -d $dir ]] || return 0
    local f
    for f in "$dir"/*.toml; do
        [[ -e $f ]] || continue
        basename "$f" .toml
    done
}

_skibidi_vpn_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    mapfile -t COMPREPLY < <(compgen -W "$(_skibidi_nodes)" -- "$cur")
}

complete -F _skibidi_vpn_complete skibidi-vpn
