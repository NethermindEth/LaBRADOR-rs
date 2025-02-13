# Condor-rs - post-quantum proof schemes and signatures


## Development

Enable [commit signing](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)

```sh
git config commit.gpgsign true
```

### Prerequisites

* [Rust](https://www.rust-lang.org/tools/install)
* [cargo deny](https://github.com/EmbarkStudios/cargo-deny)
* [typos](https://github.com/crate-ci/typos?tab=readme-ov-file#install)

### Code quality assurance

Create a pre-push git hook with the contents:

```sh
git config core.hooksPath .githooks
```
## Running the Rust Documentation Locally
After cloning the repository, follow the instructions below to run the documentation locally:
```sh
cargo doc
```
```sh
RUSTDOCFLAGS="--html-in-header katex-header.html" cargo doc --no-deps --open
```
