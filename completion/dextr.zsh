#compdef dextr

# Zsh completion for dextr
# Installation: Copy to $fpath directory or source in .zshrc

_dextr() {
    local line state

    _arguments -C \
        '1: :->command' \
        '*: :->args'

    case $state in
        command)
            local commands
            commands=(
                'generate:Generate a new encryption key file'
                'encrypt:Encrypt files or directories into an archive'
                'decrypt:Decrypt and extract an encrypted archive'
                'verify:Verify archive structure without decrypting'
                'list:List archive contents without extracting'
                'info:Display information about a key file'
                'check:Check archive integrity with key'
                'help:Show detailed usage guide and examples'
            )
            _describe 'command' commands
            ;;
        args)
            case ${line[1]} in
                generate)
                    _arguments \
                        '--force[Overwrite existing key file]' \
                        '--password[Encrypt key file with password]' \
                        '--password-file[Read password from file]:file:_files' \
                        '*:output file:_files -g "*.dxk"'
                    ;;
                encrypt)
                    _arguments \
                        '(-k --key)'{-k,--key}'[Path to key file]:key file:_files -g "*.dxk"' \
                        '(-i --input)'{-i,--input}'[Input files/directories]:input:_files' \
                        '(-o --output)'{-o,--output}'[Output archive]:output:_files -g "*.dxe"' \
                        '--force[Overwrite existing output]' \
                        '--quiet[Suppress status messages]' \
                        '--verbose[Show detailed progress]' \
                        '--password[Prompt for password]' \
                        '--password-file[Read password from file]:file:_files'
                    ;;
                decrypt)
                    _arguments \
                        '(-k --key)'{-k,--key}'[Path to key file]:key file:_files -g "*.dxk"' \
                        '(-i --input)'{-i,--input}'[Input archive]:archive:_files -g "*.dxe"' \
                        '(-o --output)'{-o,--output}'[Output directory]:directory:_directories' \
                        '--force[Extract even if directory not empty]' \
                        '--quiet[Suppress status messages]' \
                        '--verbose[Show detailed progress]' \
                        '--password[Prompt for password]' \
                        '--password-file[Read password from file]:file:_files'
                    ;;
                verify)
                    _arguments \
                        '(-i --input)'{-i,--input}'[Archive file]:archive:_files -g "*.dxe"'
                    ;;
                list)
                    _arguments \
                        '(-k --key)'{-k,--key}'[Path to key file]:key file:_files -g "*.dxk"' \
                        '(-i --input)'{-i,--input}'[Archive file]:archive:_files -g "*.dxe"' \
                        '--quiet[Suppress status messages]' \
                        '--password[Prompt for password]' \
                        '--password-file[Read password from file]:file:_files'
                    ;;
                info)
                    _arguments \
                        '(-k --key)'{-k,--key}'[Path to key file]:key file:_files -g "*.dxk"' \
                        '--password[Prompt for password]' \
                        '--password-file[Read password from file]:file:_files'
                    ;;
                check)
                    _arguments \
                        '(-k --key)'{-k,--key}'[Path to key file]:key file:_files -g "*.dxk"' \
                        '(-i --input)'{-i,--input}'[Archive file]:archive:_files -g "*.dxe"' \
                        '--quick[Quick check (first layer only)]' \
                        '--quiet[Suppress status messages]' \
                        '--verbose[Show detailed progress]' \
                        '--password[Prompt for password]' \
                        '--password-file[Read password from file]:file:_files'
                    ;;
                help)
                    _arguments \
                        '*:topic:(security workflow examples troubleshooting)'
                    ;;
            esac
            ;;
    esac
}

_dextr "$@"
