# Bash completion for dextr
# Installation: source this file or copy to /etc/bash_completion.d/
# Usage: dextr <TAB>

_dextr_completions()
{
    local cur prev commands options
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="generate encrypt decrypt verify list info check help"

    # Complete commands
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- ${cur}) )
        return 0
    fi

    # Complete options based on command
    local command="${COMP_WORDS[1]}"

    case "${command}" in
        generate)
            options="--force --password --password-file"
            ;;
        encrypt)
            options="-k --key -i --input -o --output --force --quiet --verbose --password --password-file"
            ;;
        decrypt)
            options="-k --key -i --input -o --output --force --quiet --verbose --password --password-file"
            ;;
        verify)
            options="-i --input"
            ;;
        list)
            options="-k --key -i --input --quiet --password --password-file"
            ;;
        info)
            options="-k --key --password --password-file"
            ;;
        check)
            options="-k --key -i --input --quick --quiet --verbose --password --password-file"
            ;;
        help)
            options="security workflow examples troubleshooting"
            ;;
        *)
            return 0
            ;;
    esac

    # Handle file path completion for specific options
    case "${prev}" in
        -k|--key)
            # Complete .dxk files
            COMPREPLY=( $(compgen -f -X '!*.dxk' -- ${cur}) )
            return 0
            ;;
        -i|--input)
            # Complete .dxe files for decrypt/verify/list/check
            if [[ "${command}" == "decrypt" || "${command}" == "verify" || "${command}" == "list" || "${command}" == "check" ]]; then
                COMPREPLY=( $(compgen -f -X '!*.dxe' -- ${cur}) )
            else
                # Complete any files for encrypt
                COMPREPLY=( $(compgen -f -- ${cur}) )
            fi
            return 0
            ;;
        -o|--output)
            # Complete .dxe files for encrypt, directories for decrypt
            if [[ "${command}" == "encrypt" ]]; then
                COMPREPLY=( $(compgen -f -X '!*.dxe' -- ${cur}) )
            else
                COMPREPLY=( $(compgen -d -- ${cur}) )
            fi
            return 0
            ;;
        --password-file)
            # Complete any file
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
    esac

    # Complete options
    COMPREPLY=( $(compgen -W "${options}" -- ${cur}) )
    return 0
}

complete -F _dextr_completions dextr
