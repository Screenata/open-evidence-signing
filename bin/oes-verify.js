#!/usr/bin/env node
import('../dist/cli.js').then(
  (m) => m.run(process.argv.slice(2)).then((code) => process.exit(code)),
  (e) => {
    process.stderr.write(`fatal: ${e?.message ?? e}\n`);
    process.exit(2);
  }
);
