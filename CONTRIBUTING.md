# Contributing

Thanks for helping improve accel-ppp. Please keep changes focused and easy to review.

## Code style & quality
- The current style in this repo is not perfect.
- We will demand better styling from new contributions and gradually improve the codebase.
- Match the local file style. For C, this is generally Linux kernel style / K&R-like:
  - Use hard tabs for indentation (8-column tab stops); avoid spaces for leading indent.
  - Function definitions: opening brace on the next line.
  - Control blocks (`if/for/while/switch`): opening brace on the same line.
  - `else` and `while` (for do-while) align with the closing brace.
- Prefer this layout:

```c
int foo(int x)
{
	if (x > 0) {
		bar(x);
	} else {
		baz();
	}
}
```
  - References:
    - Linux kernel coding style: `https://www.kernel.org/doc/html/latest/process/coding-style.html`
    - K&R brace/indent style overview: `https://en.wikipedia.org/wiki/Indentation_style`
- Prefer small, focused functions and avoid unnecessary churn.

## Commits (recommended, not strict)
- Use concise, imperative messages (e.g., "cli: fix output formatting").
- A simple component prefix is helpful but not required.
- Squash or group related changes when it improves clarity.

## AI-generated or assisted code
- We do not have a final policy decision yet.
- If you use AI assistance, you must review and edit your patches.
- Obvious slop, hallucinations, or nonsense will be rejected immediately.

## Tests & docs
- Run relevant tests when possible; note what you ran in the PR/commit.
- Update docs and man pages if behavior or options change.

## PR acceptance criteria
- New features or improvements must provide clear value to the accel-ppp community.
- Changes should not break existing behavior unless it is truly necessary; in such cases, contributors must make all reasonable efforts to provide a clear migration/adaptation path for users.
- Relevant tests must pass.
- Submissions must be testable by maintainers and reviewers.
- For bug fixes where trigger conditions are unclear, maintainers/reviewers may ask for details needed to reproduce the issue.

## PR review process
- We aim to review PRs within 1 week.
- If there is no maintainer activity, maintainers may be unavailable (volunteers) or the PR is too complex to review quickly.
- For major functionality changes or behavior changes, please discuss first before submitting a PR.

## Review expectations
- Please respond to review comments and update the PR as requested.
- Be prepared to rebase or adjust commits if asked by maintainers.
