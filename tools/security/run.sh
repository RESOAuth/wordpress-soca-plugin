#!/bin/sh
set -eu

repo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repo_dir"

case "${1:-}" in
    psalm)
        php tests/security/check.php psalm
        cd tools/security
        exec vendor/bin/psalm --config=psalm.xml --taint-analysis --no-cache --no-progress --monochrome
        ;;
    phpcs)
        php tests/security/check.php phpcs
        exec tools/security/vendor/bin/phpcs --standard=tools/security/phpcs.xml -s
        ;;
    semgrep)
        # Local rules only. No login, remote registry, telemetry or update checks.
        export SEMGREP_APP_TOKEN='' SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
        semgrep scan --test tools/security/semgrep --metrics=off --disable-version-check
        exec semgrep scan --oss-only --config tools/security/semgrep/php.yml \
            --metrics=off --disable-version-check --strict --error \
            --exclude simple-oauth-cimd-access/vendor simple-oauth-cimd-access
        ;;
    *)
        echo 'Usage: sh tools/security/run.sh <psalm|phpcs|semgrep>' >&2
        exit 2
        ;;
esac
