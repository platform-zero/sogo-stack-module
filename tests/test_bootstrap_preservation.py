#!/usr/bin/env python3
"""Source security regression; no deployed/owner acceptance claim."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'stack.config/sogo/entrypoint.sh'

class BootstrapPreservationTests(unittest.TestCase):
    def test_no_directory_deletion_or_password_argv(self):
        text = SCRIPT.read_text()
        self.assertNotIn('DROP TABLE sogo_users', text)
        self.assertNotIn('DROP VIEW sogo_users', text)
        self.assertNotIn('-p"$MARIADB_ADMIN_PASSWORD"', text)
        self.assertNotIn('-p"$SOGO_DB_PASSWORD"', text)
        self.assertIn('MYSQL_PWD="$MARIADB_ADMIN_PASSWORD"', text)
        self.assertLess(text.index('directory_type='), text.index('CREATE DATABASE'))

    def test_legacy_view_refused_before_mutation_without_argv_secret(self):
        text = SCRIPT.read_text()
        # Execute only the pre-mutation gate, excluding container CA/setup writes.
        start = text.index(': "${DOMAIN:?')
        end = text.index('\ndb_admin <<EOSQL')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            client = root / 'mariadb'
            client.write_text('''#!/bin/bash
set -e
[[ "${MYSQL_PWD:-}" = "$EXPECTED_PRIVATE" ]] || exit 90
for arg in "$@"; do [[ "$arg" != *"$EXPECTED_PRIVATE"* ]] || exit 91; done
if [[ "$*" == *information_schema.TABLES* ]]; then printf 'VIEW\\n';
elif [[ "$*" == *'SELECT 1'* ]]; then printf '1\\n';
else touch "$MUTATION_MARKER"; exit 92; fi
''')
            client.chmod(0o755)
            marker = root / 'mutated'
            env = dict(os.environ, PATH=f'{root}:{os.environ["PATH"]}', DOMAIN='example.test', MARIADB_ADMIN_PASSWORD='source-unit-only-private', EXPECTED_PRIVATE='source-unit-only-private', SOGO_DB_PASSWORD='source-unit-db-private', SOGO_OAUTH_SECRET='source-unit-only-oidc', MUTATION_MARKER=str(marker))
            result = subprocess.run(['bash', '-euo', 'pipefail', '-c', text[start:end]], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn('preserving existing directory view', result.stderr)
            self.assertFalse(marker.exists())
            self.assertNotIn(env['EXPECTED_PRIVATE'], result.stdout + result.stderr)

if __name__ == '__main__':
    unittest.main()
