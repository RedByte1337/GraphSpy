# Contributing

Thank you for improving GraphSpy. Follow the architecture and integration rules in [`DEVELOPMENT.md`](DEVELOPMENT.md). AI-assisted contributions are welcome only when they follow [`AI_POLICY.md`](AI_POLICY.md), including disclosure in the pull-request description.

## Workflow

1. Work on a focused branch.
2. Before committing, update it from its configured upstream with `git pull --rebase --autostash`.
3. Validate the affected startup, request, or database path. For schema changes, verify both fresh initialization and migration behavior.
4. Submit a pull request that explains the behavior changed and the verification performed.

GraphSpy currently has no automated test suite. Do not claim tests were run when only source-level checks were possible.

## Commit Conventions

- Submit one focused, signed commit for a completed change. Amend it during iteration instead of adding fixup commits.
- Use the [Conventional Commits 1.0.0 specification](https://www.conventionalcommits.org/en/v1.0.0/) with a short, one-line subject and no commit body: `type(scope): summary` or `type: summary`.
- Use `feat`, `fix`, `refactor`, `test`, `docs`, or `chore` as appropriate. Omit the scope rather than using empty parentheses.
- Commit with the human contributor's configured identity. Never add an AI or LLM as a co-author or include AI-generated attribution trailers.
- The human contributor is responsible for understanding, reviewing, signing, and owning every submitted change.
- Preserve another contributor's commits and authorship on shared pull requests unless a history rewrite is explicitly agreed.

Examples: `feat(tokens): add scope filtering`, `fix(requests): preserve proxy retries`, `refactor(db): centralize migration helpers`, and `docs: explain backend routing`.

Avoid vague subjects such as `fix stuff`, empty scopes such as `feat(): add an endpoint`, multi-line messages, and AI `Co-authored-by` trailers.
