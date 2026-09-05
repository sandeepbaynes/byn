# byn completion for bash.
#
# Candidates come from `byn __complete` at each keystroke rather than being
# baked in here, so this script never goes stale as byn gains commands.
_byn_complete() {
    local cur args IFS=$'\n'
    cur="${COMP_WORDS[COMP_CWORD]}"
    # Everything after "byn" and BEFORE the cursor, then the current word --
    # quoted, so an empty one still arrives as an argument. That trailing empty
    # is what tells byn the difference between completing a half-typed command
    # and listing the options of a finished one.
    args=("${COMP_WORDS[@]:1:COMP_CWORD-1}")
    COMPREPLY=($(byn __complete "${args[@]}" "$cur" 2>/dev/null))
}
complete -o default -F _byn_complete byn
