# bash completion for desec(1)                             -*- shell-script -*-

_desec()
{
    local cur prev words cword
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion || return
    else
        # Minimal fallback when the bash-completion package is not loaded.
        COMPREPLY=()
        cur="${COMP_WORDS[COMP_CWORD]}"
        prev="${COMP_WORDS[COMP_CWORD-1]}"
        cword=$COMP_CWORD
        words=("${COMP_WORDS[@]}")
    fi

    local record_types="A AAAA AFSDB APL CAA CDNSKEY CDS CERT CNAME DHCID DNAME \
        DNSKEY DLV DS EUI48 EUI64 HINFO HTTPS KX L32 L64 LOC LP MX NAPTR NID NS \
        OPENPGPKEY PTR RP SMIMEA SPF SRV SSHFP SVCB TLSA TXT URI"

    local actions="list-tokens create-token modify-token delete-token \
        list-token-policies add-token-policy modify-token-policy \
        delete-token-policy list-domains domain-info new-domain delete-domain \
        get-records add-record change-record update-record delete-record \
        add-tlsa set-tlsa export export-zone import import-zone"

    local global_opts="-h --help -V --version --token --token-file \
        --non-blocking --blocking --debug-http"

    # Complete values for options that take a fixed set of choices or a file.
    case "$prev" in
        -t|--type)
            COMPREPLY=($(compgen -W "$record_types" -- "$cur"))
            return
            ;;
        --protocol)
            COMPREPLY=($(compgen -W "tcp udp sctp" -- "$cur"))
            return
            ;;
        --usage)
            COMPREPLY=($(compgen -W "PKIX-TA PKIX-EE DANE-TA DANE-EE" -- "$cur"))
            return
            ;;
        --selector)
            COMPREPLY=($(compgen -W "Cert SPKI" -- "$cur"))
            return
            ;;
        --match-type)
            COMPREPLY=($(compgen -W "Full SHA2-256 SHA2-512" -- "$cur"))
            return
            ;;
        -c|--certificate|-f|--file|--token-file)
            if declare -F _filedir >/dev/null 2>&1; then
                _filedir
            else
                COMPREPLY=($(compgen -f -- "$cur"))
            fi
            return
            ;;
    esac

    # Locate the sub-command (action), skipping global options and their values.
    local action="" i
    for (( i = 1; i < cword; i++ )); do
        case "${words[i]}" in
            --token|--token-file)
                (( i++ ))  # the option consumes the following argument
                ;;
            -*)
                ;;
            *)
                action="${words[i]}"
                break
                ;;
        esac
    done

    # No action yet: complete global options or the list of actions.
    if [[ -z "$action" ]]; then
        if [[ "$cur" == -* ]]; then
            COMPREPLY=($(compgen -W "$global_opts" -- "$cur"))
        else
            COMPREPLY=($(compgen -W "$actions" -- "$cur"))
        fi
        return
    fi

    # Action-specific options.
    local opts=""
    case "$action" in
        create-token)
            opts="--name --manage-tokens --create-domain --delete-domain \
                --allowed-subnets --auto-policy"
            ;;
        modify-token)
            opts="--name --manage-tokens --no-manage-tokens --create-domain \
                --no-create-domain --delete-domain --no-delete-domain \
                --allowed-subnets --auto-policy --no-auto-policy"
            ;;
        add-token-policy)
            opts="--domain -t --type -s --subname --write"
            ;;
        modify-token-policy)
            opts="--domain -t --type -s --subname --write --no-write"
            ;;
        get-records)
            opts="-t --type -s --subname"
            ;;
        add-record|change-record|update-record)
            opts="-t --type -s --subname -r --records --ttl"
            ;;
        delete-record)
            opts="-t --type -s --subname -r --records"
            ;;
        add-tlsa|set-tlsa)
            opts="-s --subname -p --ports --protocol -c --certificate --usage \
                --selector --match-type --ttl --no-check"
            ;;
        export|export-zone)
            opts="-f --file"
            ;;
        import)
            opts="-f --file --clear"
            ;;
        import-zone)
            opts="-f --file --clear -d --dry-run"
            ;;
    esac
    opts="$opts -h --help"

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    fi
    return
}
complete -F _desec desec

# ex: filetype=sh
