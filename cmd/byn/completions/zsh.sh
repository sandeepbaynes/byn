#compdef byn
# byn completion for zsh. See the bash script for why candidates are fetched
# rather than baked in.
_byn_complete() {
    local -a candidates args
    local cur
    # words[1] is "byn"; CURRENT is the index of the word under the cursor.
    args=("${(@)words[2,CURRENT-1]}")
    cur="${words[CURRENT]}"
    # "$cur" stays quoted so an empty current word is still passed along.
    candidates=("${(@f)$(byn __complete "${args[@]}" "$cur" 2>/dev/null)}")
    # A single empty line back means "no candidates", not one blank candidate.
    if [[ ${#candidates[@]} -eq 1 && -z "${candidates[1]}" ]]; then
        return 1
    fi
    compadd -- "${candidates[@]}"
}
compdef _byn_complete byn
