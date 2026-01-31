# Contributing

Thanks for helping improve accel-ppp. Please keep changes focused and easy to review.

## Code style & quality
- The current style in this repo is not perfect.
- We will demand better styling from new contributions and gradually improve the codebase.
- Match the local file style. For C, this is generally Linux kernel style / K&R-like: tabs, function braces on the next line, control braces on the same line.
- Prefer small, focused functions and avoid unnecessary churn.

## Commits (recommended, not strict)
- Use concise, imperative messages (e.g., "cli: fix output formatting").
- A simple component prefix is helpful but not required.
- Squash or group related changes when it improves clarity.
- Add a "Signed-off-by:" line if your workflow or upstream requires it.

## AI-generated or assisted code
- We do not have a final policy decision yet.
- If you use AI assistance, you must review and edit your patches.
- Obvious slop, hallucinations, or nonsense will be rejected immediately.

## Tests & docs
- Run relevant tests when possible; note what you ran in the PR/commit.
- Update docs and man pages if behavior or options change.

## PR review process
- We aim to review PRs within 1 week.
- If there is no maintainer activity, maintainers may be unavailable (volunteers) or the PR is too complex to review quickly.
- For major functionality changes or behavior changes, please discuss first before submitting a PR.

## Review expectations
- Please respond to review comments and update the PR as requested.
- Be prepared to rebase or adjust commits if asked by maintainers.
