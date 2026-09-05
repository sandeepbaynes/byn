# byn completion for fish. See the bash script for why candidates are fetched
# rather than baked in.
function __byn_complete
    set -l tokens (commandline -opc)
    set -l cur (commandline -ct)
    # tokens[1] is "byn"; drop it. An empty current word is passed explicitly so
    # byn can tell a half-typed command from a finished one.
    if test (count $tokens) -gt 1
        byn __complete $tokens[2..-1] "$cur" 2>/dev/null
    else
        byn __complete "$cur" 2>/dev/null
    end
end

# -f: no file completion by default, byn says what is valid.
complete -c byn -f -a '(__byn_complete)'
