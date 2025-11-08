# Fish completion for dextr
# Installation: Copy to ~/.config/fish/completions/

# Remove all previously defined completions for dextr
complete -c dextr -e

# Commands
complete -c dextr -n '__fish_use_subcommand' -a 'generate' -d 'Generate a new encryption key file'
complete -c dextr -n '__fish_use_subcommand' -a 'encrypt' -d 'Encrypt files or directories into an archive'
complete -c dextr -n '__fish_use_subcommand' -a 'decrypt' -d 'Decrypt and extract an encrypted archive'
complete -c dextr -n '__fish_use_subcommand' -a 'verify' -d 'Verify archive structure without decrypting'
complete -c dextr -n '__fish_use_subcommand' -a 'list' -d 'List archive contents without extracting'
complete -c dextr -n '__fish_use_subcommand' -a 'info' -d 'Display information about a key file'
complete -c dextr -n '__fish_use_subcommand' -a 'check' -d 'Check archive integrity with key'
complete -c dextr -n '__fish_use_subcommand' -a 'help' -d 'Show detailed usage guide and examples'

# Global options
complete -c dextr -l version -d 'Show version and exit'

# generate command
complete -c dextr -n '__fish_seen_subcommand_from generate' -l force -d 'Overwrite existing key file'
complete -c dextr -n '__fish_seen_subcommand_from generate' -l password -d 'Encrypt key file with password'
complete -c dextr -n '__fish_seen_subcommand_from generate' -l password-file -d 'Read password from file' -F

# encrypt command
complete -c dextr -n '__fish_seen_subcommand_from encrypt' -s k -l key -d 'Path to key file' -r -F
complete -c dextr -n '__fish_seen_subcommand_from encrypt' -s i -l input -d 'Input files/directories' -r -F
complete -c dextr -n '__fish_seen_subcommand_from encrypt' -s o -l output -d 'Output archive (.dxe)' -r -F
complete -c dextr -n '__fish_seen_subcommand_from encrypt' -l force -d 'Overwrite existing output'
complete -c dextr -n '__fish_seen_subcommand_from encrypt' -l quiet -d 'Suppress status messages'
complete -c dextr -n '__fish_seen_subcommand_from encrypt' -l verbose -d 'Show detailed progress'
complete -c dextr -n '__fish_seen_subcommand_from encrypt' -l password -d 'Prompt for password'
complete -c dextr -n '__fish_seen_subcommand_from encrypt' -l password-file -d 'Read password from file' -F

# decrypt command
complete -c dextr -n '__fish_seen_subcommand_from decrypt' -s k -l key -d 'Path to key file' -r -F
complete -c dextr -n '__fish_seen_subcommand_from decrypt' -s i -l input -d 'Input archive (.dxe)' -r -F
complete -c dextr -n '__fish_seen_subcommand_from decrypt' -s o -l output -d 'Output directory' -r -F
complete -c dextr -n '__fish_seen_subcommand_from decrypt' -l force -d 'Extract even if directory not empty'
complete -c dextr -n '__fish_seen_subcommand_from decrypt' -l quiet -d 'Suppress status messages'
complete -c dextr -n '__fish_seen_subcommand_from decrypt' -l verbose -d 'Show detailed progress'
complete -c dextr -n '__fish_seen_subcommand_from decrypt' -l password -d 'Prompt for password'
complete -c dextr -n '__fish_seen_subcommand_from decrypt' -l password-file -d 'Read password from file' -F

# verify command
complete -c dextr -n '__fish_seen_subcommand_from verify' -s i -l input -d 'Archive file (.dxe)' -r -F

# list command
complete -c dextr -n '__fish_seen_subcommand_from list' -s k -l key -d 'Path to key file' -r -F
complete -c dextr -n '__fish_seen_subcommand_from list' -s i -l input -d 'Archive file (.dxe)' -r -F
complete -c dextr -n '__fish_seen_subcommand_from list' -l quiet -d 'Suppress status messages'
complete -c dextr -n '__fish_seen_subcommand_from list' -l password -d 'Prompt for password'
complete -c dextr -n '__fish_seen_subcommand_from list' -l password-file -d 'Read password from file' -F

# info command
complete -c dextr -n '__fish_seen_subcommand_from info' -s k -l key -d 'Path to key file' -r -F
complete -c dextr -n '__fish_seen_subcommand_from info' -l password -d 'Prompt for password'
complete -c dextr -n '__fish_seen_subcommand_from info' -l password-file -d 'Read password from file' -F

# check command
complete -c dextr -n '__fish_seen_subcommand_from check' -s k -l key -d 'Path to key file' -r -F
complete -c dextr -n '__fish_seen_subcommand_from check' -s i -l input -d 'Archive file (.dxe)' -r -F
complete -c dextr -n '__fish_seen_subcommand_from check' -l quick -d 'Quick check (first layer only)'
complete -c dextr -n '__fish_seen_subcommand_from check' -l quiet -d 'Suppress status messages'
complete -c dextr -n '__fish_seen_subcommand_from check' -l verbose -d 'Show detailed progress'
complete -c dextr -n '__fish_seen_subcommand_from check' -l password -d 'Prompt for password'
complete -c dextr -n '__fish_seen_subcommand_from check' -l password-file -d 'Read password from file' -F

# help command
complete -c dextr -n '__fish_seen_subcommand_from help' -a 'security' -d 'Security information'
complete -c dextr -n '__fish_seen_subcommand_from help' -a 'workflow' -d 'Common workflows'
complete -c dextr -n '__fish_seen_subcommand_from help' -a 'examples' -d 'Command examples'
complete -c dextr -n '__fish_seen_subcommand_from help' -a 'troubleshooting' -d 'Troubleshooting guide'
