#!/bin/bash
# verify_readme_modules.sh - Ensure README's Project Structure matches repository modules.
set -euo pipefail

# Extract module names from Project Structure section
readme_modules=$(awk '/## Project Structure/{flag=1;next}/^---/{flag=0}flag' README.md \
    | grep -o '`[^`]*`' | tr -d '`,' | sed 's|.*/||' | sort -u)

status=0

# Check that every referenced module exists
for m in $readme_modules; do
    path=$m
    # Skip URLs and inline references
    if [[ $path == *://* ]]; then
        continue
    fi
    # Skip CLI flags and tokens that aren't typical file names
    if [[ $path == -* ]] || [[ $path == .sha256 ]]; then
        continue
    fi
    if [[ $path == press.conf ]]; then
        continue
    fi
    ext=${path##*.}
    case $ext in
        sh|py|ps1|cfg|conf|desktop|service|timer|example|yaml|md) ;;
        *) continue ;;
    esac
    # For paths like /etc/nn_ids.conf use basename
    if [[ $path == /* ]]; then
        path=$(basename "$path")
    fi
    if [[ ! -e $path ]]; then
        echo "Missing module: $path" >&2
        status=1
    fi
done

# Warn about modules that are not documented in the README
repo_modules=$(find . -maxdepth 1 -type f \
    \( -name '*.sh' -o -name '*.py' -o -name '*.ps1' -o -name '*.cfg' -o -name '*.conf' -o -name '*.desktop' -o -name '*.service' -o -name '*.timer' \) \
    -printf '%f\n' | sort -u)
for f in $repo_modules; do
    if ! grep -Fqx "$f" <<< "$readme_modules"; then
        echo "Undocumented module: $f" >&2
        status=1
    fi
done

if [[ $status -eq 0 ]]; then
    echo "README.md project structure matches repository modules."
fi

exit $status
