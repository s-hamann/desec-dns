#!/usr/bin/env bash
# Check the encoding of all files in the repository. Raise an error if any file
# is not ASCII. Exceptions for specific files can be configured in
# $known_non_ascii_files.
# The purpose of this script is to detect homoglyph attacks.

shopt -s lastpipe

declare -A known_non_ascii_files
known_non_ascii_files[.github/release.yml]=utf-8
known_non_ascii_files[tests/files/test_tlsa_record.der]=binary

declare -A unexpected_encoding_files

git ls-files | while read -r file; do
    [[ ! -s "${file}" ]] && continue
    enc="$(file --brief --mime-encoding "${file}")"
    [[ "${enc}" = "${known_non_ascii_files["${file}"]:-us-ascii}" ]] && continue
    unexpected_encoding_files["${file}"]="${enc}"
done

if [[ "${#unexpected_encoding_files[@]}" -gt 0 ]]; then
    for file in "${!unexpected_encoding_files[@]}"; do
        if [[ -n "${GITHUB_ACTIONS}" ]]; then
            printf '::error file=%s,line=1::%s has unexpected file encoding "%s" instead of "%s"\n' "${file}" "${file}" "${unexpected_encoding_files["${file}"]}" "${known_non_ascii_files["${file}"]:-us-ascii}"
        else
            printf '%s: unexpected file encoding "%s" instead of "%s"\n' "${file}" "${unexpected_encoding_files["${file}"]}" "${known_non_ascii_files["${file}"]:-us-ascii}"
        fi
    done
    exit 1
fi
