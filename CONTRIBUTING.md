# Contributing to the Stacks Blockchain

The Stacks blockchain is open-source software written in Rust. Contributions
should adhere to the following best practices.

Blockchain software development requires a much higher degree of rigor
than most other kinds of software. This is because with blockchains,
**there is no roll-back** from a bad deployment. There is essentially
zero room for consensus bugs. If you ship a consensus bug, that bug
could not only have catastrophic consequences for users (i.e. they
lose all their money), but also be intractable to fix, mitigate, or
remove. This is because unlike nearly every other kind of networked
software, **the state of the blockchain is what the users' computers
say it is.** If you want to make changes, you _must_ get _user_
buy-in, and this is necessarily time-consuming and not at all
guaranteed to succeed.

You can find information on joining online community forums (Discord, mailing list etc.) in the [README](README.md).

# Code of Conduct

This project and everyone participating in it is governed by this [Code of Conduct](CODE_OF_CONDUCT.md).

# How Can I Contribute?

## Development Workflow

See the branching document in [branching.md](./docs/branching.md).

### Merging PRs from Forks

PRs from forks or opened by contributors without commit access require
some special handling for merging. Any such PR, after being reviewed,
must get assigned to a contributor with commit access. This merge-owner
is responsible for:

1. Creating a new branch in this repository based on the base branch
   for the PR.
2. Retargeting the PR toward the new branch.
3. Merging the PR into the new branch.
4. Opening a new PR from `new_branch -> original_base`
5. Tagging reviewers for re-approval.
6. Merging the new PR.

For an example of this process, see PRs
[#3598](https://github.com/stacks-network/stacks-core/pull/3598) and
[#3626](https://github.com/stacks-network/stacks-core/pull/3626).

### Documentation Updates

- Any major changes should be added to the [CHANGELOG](CHANGELOG.md).
- Mention any required documentation changes in the description of your pull request.
- If adding or updating an RPC endpoint, ensure the change is documented in the
  OpenAPI spec: [`./docs/rpc/openapi.yaml`](./docs/rpc/openapi.yaml).
- If your code adds or modifies any major features (struct, trait,
  test, module, function, etc.), each should be documented according
  to our [coding guidelines](#Coding-Guidelines).

## Git Commit Messages

Aim to use descriptive git commit messages. We try to follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/).
The general format is as follows:

```
<type>[optional scope]: <one-line description>

[optional body]
[optional footer(s)]
```

Common types include build, ci, docs, fix, feat, test, refactor, etc.

When a commit is addressing or related to a particular Github issue, it
should reference the issue in the commit message. For example:

```
fix: incorporate unlocks in mempool admitter, #3623
```

## Recommended developer setup

### Recommended githooks

It is helpful to set up the pre-commit git hook set up, so that Rust formatting issues are caught before
you push your code. Follow these instruction to set it up:

1. Rename `.git/hooks/pre-commit.sample` to `.git/hooks/pre-commit`
2. Change the content of `.git/hooks/pre-commit` to be the following

```sh
#!/bin/sh
git diff --name-only --staged | grep '\.rs$' | xargs -P 8 -I {} rustfmt {} --edition 2021 --check --config group_imports=StdExternalCrate,imports_granularity=Module || (
  echo 'rustfmt failed: run "cargo fmt-stacks"';
  exit 1
)
```

3. Make it executable by running `chmod +x .git/hooks/pre-commit`
   That's it! Now your pre-commit hook should be configured on your local machine.

# Creating and Reviewing PRs

This section describes some best practices on how to create and review PRs in this context. The target audience is people who have commit access to this repository (reviewers), and people who open PRs (submitters). This is a living document -- developers can and should document their own additional guidelines here.

## Overview

Blockchain software development requires a much higher degree of rigor than most other kinds of software. This is because with blockchains, **there is no roll-back** from a bad deployment.

Therefore, making changes to the codebase is necessarily a review-intensive process. No one wants bugs, but **no one can afford consensus bugs**. This page describes how to make and review _non-consensus_ changes. The process for consensus changes includes not only the entirety of this document, but also the [SIP process](https://github.com/stacksgov/sips/blob/main/sips/sip-000/sip-000-stacks-improvement-proposal-process.md).

A good PR review sets both the submitter and reviewers up for success. It minimizes the time required by both parties to get the code into an acceptable state, without sacrificing quality or safety. Unlike most other software development practices, _safety_ is the primary concern. A PR can and will be delayed or closed if there is any concern that it will lead to unintended consensus-breaking changes.

This document is formatted like a checklist. Each paragraph is one goal or action item that the reviewer and/or submitter must complete. The **key take-away** from each paragraph is bolded.

## Reviewer Expectations

The overall task of a reviewer is to create an **acceptance plan** for the submitter. This is simply the list of things that the submitter _must_ do in order for the PR to be merged. The acceptance plan should be coherent, cohesive, succinct, and complete enough that the reviewer will understand exactly what they need to do to make the PR worthy of merging, without further reviews. The _lack of ambiguity_ is the most important trait of an acceptance plan.

Reviewers should **complete the review in one round**. The reviewer should provide enough detail to the submitter that the submitter can make all of the requested changes without further supervision. Whenever possible, the reviewer should provide all of these details publicly as comments, so that _other_ reviewers can vet them as well. If a reviewer _cannot_ complete the review in one round due to its size and complexity, then the reviewer may request that the PR be simplified or broken into multiple PRs.

Reviewers should make use of Github's "pending comments" feature. This ensures that the review is "atomic": when the reviewer submits the review, all the comments are published at once.

Reviewers should aim to **perform a review in one sitting** whenever possible. This enables a reviewer to time-box their review, and ensures that by the time they finish studying the patch, they have a complete understanding of what the PR does in their head. This, in turn, sets them up for success when writing up the acceptance plan. It also enables reviewers to mark time for it on their calendars, which helps everyone else develop reasonable expectations as to when things will be done.

Code reviews should be timely. Reviewers should start no more than
**2 business days** after reviewers are assigned. This applies to each
reviewer: i.e., we expect all reviewers to respond within two days.
The `develop` and `next` branches in particular often change quickly,
so letting a PR languish only creates more merge work for the
submitter. If a review cannot be started within this timeframe, then
the reviewers should **tell the submitter when they can begin**. This
gives the reviewer the opportunity to keep working on the PR (if
needed) or even withdraw and resubmit it.

Reviewers must, above all else, **ensure that submitters follow the PR checklist** below.

**As a reviewer, if you do not understand the PR's code or the potential consequences of the code, it is the submitter's responsibility to simplify the code, provide better documentation, or withdraw the PR.**

## Submitter Expectations

Everyone is busy all the time with a host of different tasks. Consequently, a PR's size and scope should be constrained so that **a review can be written for it no more than 2 hours.** This time block starts when the reviewer opens the patch, and ends when the reviewer hits the "submit review" button. If it takes more than 2 hours, then the PR should be broken into multiple PRs unless the reviewers agree to spend more time on it. A PR can be rejected if the reviewers believe they will need longer than this.

The size and scale of a PR depend on the reviewers' abilities to process the change. Different reviewers and submitters have different levels of familiarity with the codebase. Moreover, everyone has a different schedule -- sometimes, some people are more busy than others.

A successful PR submitter **takes the reviewers' familiarity and availability into account** when crafting the PR, even going so far as to ask in advance if a particular person could be available for review.

Providing detailed answers to reviewer questions is often necessary as a submitter. In order to make this information accessible even after a PR has merged, **submitters should strive to incorporate any clarifications into code comments**.

**Selecting Reviewers**. PR submitters may tag reviewers that they
think are relevant to the code changes in the PR (or using the
reviewer suggestions provided by Github). If a PR is submitted without
assigned reviewers, then reviewers will be assigned at least by the next
Weekly Blockchain Engineering Meeting (information can be found in Discord).

## Submission Checklist

A PR submission's text should **answer the following questions** for reviewers:

- What problem is being solved by this PR?
- What does the solution do to address them?
- Why is this the best solution? What alternatives were considered, and why are they worse?
- What do reviewers need to be familiar with in order to provide useful feedback?
- What issue(s) are addressed by this PR?
- What are some hints to understanding some of the more intricate or clever parts of the PR?
- Does this PR change any database schemas? Does a node need to re-sync from genesis when this PR is applied?

In addition, the PR submission should **answer the prompts of the Github template** we use for PRs.

The code itself should adhere to our coding guidelines and conventions, which both submitters and reviewers should check.

# Coding Conventions

### Simplicity of implementation

The most important consideration when accepting or rejecting a contribution is
the simplicity (i.e. ease of understanding) of its implementation.
Contributions that are "clever" or introduce functionality beyond the scope of
the immediate problem they are meant to solve will be rejected.

#### Type simplicity

Simplicity of implementation includes simplicity of types. Type parameters
and associated types should only be used if there are at
least two possible implementations of those types.

Lifetime parameters should only be introduced if the compiler cannot deduce them
on its own.

### Builds with a stable Rust compiler

We use a recent, stable Rust compiler. Contributions should _not_
require nightly Rust features to build and run.

### Minimal dependencies

Adding new package dependencies is very much discouraged. Exceptions will be
granted on a case-by-case basis, and only if deemed absolutely necessary.

### Minimal global macros

Adding new global macros is discouraged. Exceptions will only be given if
absolutely necessary.

### No compiler warnings

Contributions should not trigger compiler warnings if possible, and should not
mask compiler warnings with macros.

### Minimal `unsafe` code

Contributions should not contain `unsafe` blocks if at all possible.

# Coding Guidelines

## Documentation

- Each file must have a **copyright statement**.
- Any new non-test modules should have **module-level documentation** explaining what the module does, and how it fits into the blockchain as a whole ([example](https://github.com/stacks-network/stacks-core/blob/4852d6439b473e24705f14b8af637aded33cb422/testnet/stacks-node/src/neon_node.rs#L17)).
- Any new files must have some **top-of-file documentation** that describes what the contained code does, and how it fits into the overall module.

Within the source files, the following **code documentation** standards are expected:

- Each public function, struct, enum, and trait should have a Rustdoc comment block describing the API contract it offers. This goes for private structs and traits as well.
- Each _non-trivial_ private function should likewise have a Rustdoc comment block. Trivial ones that are self-explanatory, like getters and setters, do not need documentation. If you are unsure if your function needs a docstring, err on the side of documenting it.
- Each struct and enum member must have a Rustdoc comment string indicating what it does, and how it is used. This can be as little as a one-liner, as long as the relevant information is communicated.

## Factoring

- **Each non-`mod.rs` file implements at most one subsystem**. It may include multiple struct implementations and trait implementations. The filename should succinctly identify the subsystem, and the file-level documentation must succinctly describe it and how it relates to other subsystems it interacts with.

- Directories represent collections of related but distinct subsystems.

- To the greatest extent possible, **business logic and I/O should be
  separated**. A common pattern used in the codebase is to place the
  business logic into an "inner" function that does not do I/O, and
  handle I/O reads and writes in an "outer" function. The "outer"
  function only does the needful I/O and passes the data into the
  "inner" function. The "inner" function is often private, whereas
  the "outer" function is often public. For example, [`inner_try_mine_microblock` and `try_mine_microblock`](https://github.com/stacks-network/stacks-core/blob/4852d6439b473e24705f14b8af637aded33cb422/testnet/stacks-node/src/neon_node.rs#L1148-L1216).

## Refactoring

- **Any PR that does a large-scale refactoring must be in its own PR**. This includes PRs that touch multiple subsystems. Refactoring often adds line noise that obscures the new functional changes that the PR proposes. Small-scale refactorings are permitted to ship with functional changes.

- Refactoring PRs can generally be bigger, because they are easier to review. However, **large refactorings that could impact the functional behavior of the system should be discussed first** before carried out. This is because it is imperative that they do not stay open for very long (to keep the submitter's maintenance burden low), but nevertheless reviewing them must still take at most 2 hours. Discussing them first front-loads part of the review process.

## Databases

- If at all possible, **the database schema should be preserved**. Exceptions can be made on a case-by-case basis. The reason for this is that it's a big ask for people to re-sync nodes from genesis when they upgrade to a new point release.

- Any changes to a database schema must also ship with a **new schema version and new schema migration logic**, as well as _test coverage_ for it.

- The submitter must verify that **any new database columns are indexed**, as relevant to the queries performed on them. Table scans are not permitted if they can be avoided (and they almost always can be). You can find table scans manually by setting the environment variable `BLOCKSTACK_DB_TRACE` when running your tests (this will cause every query executed to be preceded by the output of `EXPLAIN QUERY PLAN` on it).

- Database changes **cannot be consensus-critical** unless part of a hard fork (see below).

- If the database schema changes and no migration can be feasibly done, then the submitter **must spin up a node from genesis to verify that it works** _before_ submitting the PR. This genesis spin-up will be tested again before the next node release is made.

## Data Input

- **Data from the network, from Bitcoin, and from the config file is untrusted.** Code that ingests such data _cannot assume anything_ about its structure, and _must_ handle any possible byte sequence that can be submitted to the Stacks node.

- **Data previously written to disk by the node is trusted.** If data loaded from the database that was previously stored by the node is invalid or corrupt, it is appropriate to panic.

- **All input processing is space-bound.** Every piece of code that ingests data must impose a maximum size on its byte representation. Any inputs that exceed this size _must be discarded with as little processing as possible_.

- **All input deserialization is resource-bound.** Every piece of code
  that ingests data must impose a maximum amount of RAM and CPU
  required to decode it into a structured representation. If the data
  does not decode with the allotted resources, then no further
  processing may be done and the data is discarded. For an example, see
  how the parsing functions in the http module use `BoundReader` and
  `MAX_PAYLOAD_LEN` in [http.rs](https://github.com/stacks-network/stacks-core/blob/4852d6439b473e24705f14b8af637aded33cb422/src/net/http.rs#L2260-L2285).

- **All network input reception is time-bound.** Every piece of code that ingests data _from the network_ must impose a maximum amount of time that ingestion can take. If the data takes too long to arrive, then it must be discarded without any further processing. There is no time bound for data ingested from disk or passed as an argument; this requirement is meant by the space-bound requirement.

- **Untrusted data ingestion must not panic.** Every piece of code that ingests untrusted data must gracefully handle errors. Panicking failures are forbidden for such data. Panics are only allowed if the ingested data was previously written by the node (and thus trusted).

## Non-consensus Changes to Blocks, Microblocks, Transactions, and Clarity

Any changes to code that alters how a block, microblock, or transaction is processed by the node should be **treated as a breaking change until proven otherwise**. This includes changes to the Clarity VM. The reviewer _must_ flag any such changes in the PR, and the submitter _must_ convince _all_ reviewers that they will _not_ break consensus.

Changes that touch any of these four code paths must be treated with the utmost care. If _any_ core developer suspects that a given PR would break consensus, then they _must_ act to prevent the PR from merging.

## Changes to the Peer Network

Any changes to the peer networking code **must be run on both mainnet and testnet before the PR can be merged.** The submitter should set up a testable node or set of nodes that reviewers can interact with.

Changes to the peer network should be deployed incrementally and tested by multiple parties when possible to verify that they function properly in a production setting.

## Performance Improvements

Any PRs that claim to improve performance **must ship with reproducible benchmarks** that accurately measure the improvement. This data must also be reported in the PR submission.

For an example, see [PR #3075](https://github.com/stacks-network/stacks-core/pull/3075).

## Error Handling

- **Results must use `Error` types**. Fallible functions in the
  codebase must use `Error` types in their `Result`s. If a new module's
  errors are sufficiently different from existing `Error` types in the
  codebaes, the new module must define a new `Error` type. Errors that
  are caused by other `Error` types should be wrapped in a variant of
  the new `Error` type. You should provide conversions via a `From`
  trait implementation.

- Functions that act on externally-submitted data **must never panic**. This includes code that acts on incoming network messages, blockchain data, and burnchain (Bitcoin) data.

- **Runtime panics should be used sparingly**. Generally speaking, a runtime panic is only appropriate if there is no reasonable way to recover from the error condition. For example, this includes (but is not limited to) disk I/O errors, database corruption, and unreachable code.

- If a runtime panic is desired, it **must have an appropriate error message**.

## Logging

- Log messages should be informative and context-free as possible. They are used mainly to help us identify and diagnose problems. They are _not_ used to help you verify that your code works; that's the job of a unit test.

- **DO NOT USE println!() OR eprintln!()**. Instead, use the logging macros (`test_debug!()`, `trace!()`, `debug!()`, `info!()`, `warn!()`, `error!()`).

- Use **structured logging** to include dynamic data in your log entry. For example, `info!("Append block"; "block_id" => %block_id)` as opposed to `info!("Append block with block_id = {}", block_id)`.

- Use `trace!()` and `test_debug!()` liberally. It only runs in tests.

- Use `debug!()` for information that is relevant for diagnosing problems at runtime. This is off by default, but can be turned on with the `BLOCKSTACK_DEBUG` environment variable.

- Use `info!()` sparingly.

- Use `warn!()` or `error!()` only when there really is a problem.

## Consensus-Critical Code

A **consensus-critical change** is a change that affects how the Stacks blockchain processes blocks, microblocks, or transactions, such that a node with the patch _could_ produce a different state root hash than a node without the patch. If this is even _possible_, then the PR is automatically treated as a consensus-critical change and must ship as part of a hard fork. It must also be described in a SIP.

- **All changes to consensus-critical code must be opened against `next`**. It is _never acceptable_ to open them against `develop` or `master`.

- **All consensus-critical changes must be gated on the Stacks epoch**. They may only take effect once the system enters a specific epoch (and this must be documented).

A non-exhaustive list of examples of consensus-critical changes include:

- Adding or changing block, microblock, or transaction wire formats
- Changing the criteria under which a burnchain operation will be accepted by the node
- Changing the data that gets stored to a MARF key/value pair in the Clarity or Stacks chainstate MARFs
- Changing the order in which data gets stored in the above
- Adding, changing, or removing Clarity functions
- Changing the cost of a Clarity function
- Adding new kinds of transactions, or enabling certain transaction data field values that were previously forbidden.

## Testing

- **Unit tests should focus on the business logic with mocked data**. To the greatest extent possible, each error path should be tested _in addition to_ the success path. A submitter should expect to spend most of their test-writing time focusing on error paths; getting the success path to work is often much easier than the error paths.

- **Unit tests should verify that the I/O code paths work**, but do so in a way that does not "clobber" other tests or prevent other tests from running in parallel (if it can be avoided). This means that unit tests should use their own directories for storing transient state (in `/tmp`), and should bind on ports that are not used anywhere else.

- If randomness is needed, **tests should use a seeded random number generator if possible**. This ensures that they will reliably pass in CI.

- When testing a consensus-critical code path, the test coverage should verify that the new behavior is only possible within the epoch(s) in which the behavior is slated to activate. Above all else, **backwards-compatibility is a hard requirement.**

- **Integration tests are necessary when the PR has a consumer-visible effect**. For example, changes to the RESTful API, event stream, and mining behavior all require integration tests.

- Every consensus-critical change needs an integration test to verify that the feature activates only when the hard fork activates.

PRs must include test coverage. However, if your PR includes large tests or tests which cannot run in parallel
(which is the default operation of the `cargo test` command), these tests should be decorated with `#[ignore]`.

A test should be marked `#[ignore]` if:

1. It does not _always_ pass `cargo test` in a vanilla environment
   (i.e., it does not need to run with `--test-threads 1`).

2. Or, it runs for over a minute via a normal `cargo test` execution
   (the `cargo test` command will warn if this is not the case).

## Formatting

PRs will be checked against `rustfmt` and will _fail_ if not properly formatted.
Unfortunately, some config options that we require cannot currently be set in `.rustfmt` files, so arguments must be passed via the command line.
Therefore, we handle `rustfmt` configuration using a Cargo alias: `cargo fmt-stacks`

You can check the formatting locally via:

```bash
cargo fmt-stacks --check
```

You can automatically reformat your commit via:

```bash
cargo fmt-stacks
```

## Clippy Warnings

PRs will be checked against `clippy` and will _fail_ if any clippy warnings are generated.
Unfortunately, not all existing clippy warnings have been addressed throughout stacks-core, so arguments must be passed via the command line. 
Therefore, we handle `clippy` configurations using a Cargo alias: `cargo clippy-stacks`

You can check what warnings need to be addressed locally via: 

```bash
cargo clippy-stacks
```

## Comments

Comments are very important for the readability and correctness of the codebase. The purpose of comments is:

- Allow readers to understand the roles of components and functions without having to check how they are used.
- Allow readers to check the correctness of the code against the comments.
- Allow readers to follow tests.

In the limit, if there are no comments, the problems that arise are:

- Understanding one part of the code requires understanding _many_ parts of the code. This is because the reader is forced to learn the meanings of constructs inductively through their use. Learning how one construct is used requires understanding its neighbors, and then their neighbors, and so on, recursively. Instead, with a good comment, the reader can understand the role of a construct with `O(1)` work by reading the comment.
- The user cannot be certain if there is a bug in the code, because there is no distinction between the contract of a function, and its definition.
- The user cannot be sure if a test is correct, because the logic of the test is not specified, and the functions do not have contracts.

### Comment Formatting

Comments are to be formatted in typical `rust` style, specifically:

- Use markdown to format comments.

- Use the triple forward slash "///" for modules, structs, enums, traits and functions. Use double forward slash "//" for comments on individual lines of code.

- Start with a high-level description of the function, adding more sentences with details if necessary.

- When documenting panics, errors, or other conceptual sections, introduce a Markdown section with a single `#`, e.g.:

  ```rust
  # Errors
  * ContractTooLargeError: Thrown when `contract` is larger than `MAX_CONTRACT_SIZE`.
  ```

### Content of Comments

#### Component Comments

Comments for a component (`struct`, `trait`, or `enum`) should explain what the overall
purpose of that component is. This is usually a concept, and not a formal contract. Include anything that is not obvious about this component.

**Example:**

```rust
/// The `ReadOnlyChecker` analyzes a contract to determine whether
/// there are any violations of read-only declarations. By a "violation"
/// we mean a function that is marked as "read only" but which tries
/// to modify chainstate.
pub struct ReadOnlyChecker<'a, 'b> {
```

This comment is considered positive because it explains the concept behind the class at a glance, so that the reader has some idea about what the methods will achieve, without reading each method declaration and comment. It also defines some terms that can be used in the comments on the method names.

#### Function Comments

The comments on a function should explain what the function does, without having to read it. Wherever practical, it should specify the contract of a function, such that a bug in the logic could be discovered by a discrepancy between contract and implementation, or such that a test could be written with only access to the function comment.

Without being unnecessarily verbose, explain how the output is calculated
from the inputs. Explain the side effects. Explain any restrictions on the inputs. Explain failure
conditions, including when the function will panic, return an error
or return an empty value.

**Example:**

```rust
/// A contract that does not violate its read-only declarations is called
/// *read-only correct*.
impl<'a, 'b> ReadOnlyChecker<'a, 'b> {
    /// Checks each top-level expression in `contract_analysis.expressions`
    /// for read-only correctness.
    ///
    /// Returns successfully iff this function is read-only correct.
    ///
    /// # Errors
    ///
    /// - Returns CheckErrors::WriteAttemptedInReadOnly if there is a read-only
    ///   violation, i.e. if some function marked read-only attempts to modify
    ///   the chainstate.
    pub fn run(&mut self, contract_analysis: &ContractAnalysis) -> CheckResult<()>
```

This comment is considered positive because it explains the contract of the function in pseudo-code. Someone who understands the constructs mentioned could, e.g., write a test for this method from this description.

#### Comments on Implementations of Virtual Methods

Note that, if a function implements a virtual function on an interface, the comments should not
repeat what was specified on the interface declaration. The comment should only add information specific to that implementation.

#### Data Member Comments

Each data member in a struct should have a comment describing what that member
is, and what it is used for. Such comments are usually brief but should
clear up any ambiguity that might result from having only the variable
name and type.

**Example:**

```rust
pub struct ReadOnlyChecker<'a, 'b> {
    /// Mapping from function name to a boolean indicating whether
    /// the function with that name is read-only.
    /// This map contains all functions in the contract analyzed.
    defined_functions: HashMap<ClarityName, bool>,
```

This comment is considered positive because it clarifies users might have about the content and role of this member. E.g., it explains that the `bool` indicates whether the function is _read-only_, whereas this cannot be gotten from the signature alone.

#### Test Comments

Each test should have enough comments to help an unfamiliar reader understand:

1. what is conceptually being tested
1. why a given answer is expected

Sometimes this can be obvious without much comments, perhaps from the context,
or because the test is very simple. Often though, comments are necessary.

**Example:**

```rust
#[test]
#[ignore]
/// The purpose of this test is to check if the mempool admission checks
/// for the post tx endpoint are working as expected wrt the optional
/// `mempool_admission_check` query parameter.
///
/// In this test, we are manually creating a microblock as well as
/// reloading the unconfirmed state of the chainstate, instead of relying
/// on `next_block_and_wait` to generate microblocks. We do this because
/// the unconfirmed state is not automatically being initialized
/// on the node, so attempting to validate any transactions against the
/// expected unconfirmed state fails.
fn transaction_validation_integration_test() {
```

This comment is considered positive because it explains the purpose of the test (checking the case of an optional parameter), it also guides the reader to understand the low-level details about why a microblock is created manually.

### How Much to Comment

Contributors should strike a balance between commenting "too much" and commenting "too little". Commenting "too much" primarily includes commenting things that are clear from the context. Commenting "too little" primarily includes writing no comments at all, or writing comments that leave important questions unresolved.

Human judgment and creativity must be used to create good comments, which convey important information with small amounts of text. There is no single rule which can determine what a good comment is. Longer comments are _not_ always better, since needlessly long comments have a cost: they require the reader to read more, take up whitespace, and take longer to write and review.

### Don't Restate Names in Comments

The contracts of functions should be implemented precisely enough that tests could be written looking only at the declaration and the comments (and without looking at the definition!). However:

- **the author should assume that the reader has already read and understood the function name, variable names, type names, etc.**
- **the author should only state information that is new**

So, if a function and its variables have very descriptive names, then there may be nothing to add in the comments at all!

**Bad Example**

```rust
/// Appends a transaction to a block.
fn append_transaction_to_block(transaction:Transaction, &mut Block) -> Result<()>
```

This is considered bad because the function name already says "append transaction to block", so it doesn't add anything to restate it in the comments. However, _do_ add anything that is not redundant, such as elaborating what it means to "append" (if there is more to say), or what conditions will lead to an error.

**Good Example**

```rust
/// # Errors
///
/// - BlockTooBigError: Is returned if adding `transaction` to `block` results
/// in a block size bigger than MAX_BLOCK_SIZE.
fn append_transaction_to_block(transaction:Transaction, block:&mut Block) -> Result<()>
```

This is considered good because the reader builds on the context created by the function and variable names. Rather than restating them, the function just adds elements of the contract that are not implicit in the declaration.

### Do's and Dont's of Comments

_Don't_ over-comment by documenting things that are clear from the context. E.g.:

- Don't document the types of inputs or outputs, since these are parts of the type signature in `rust`.
- Don't necessarily document standard "getters" and "setters", like `get_clarity_version()`, unless there is unexpected information to add with the comment.
- Don't explain that a specific test does type-checking, if it is in a file that is dedicated to type-checking.

_Do_ document things that are not clear, e.g.:

- For a function called `process_block`, explain what it means to "process" a block.
- For a function called `process_block`, make clear whether we mean anchored blocks, microblocks, or both.
- For a function called `run`, explain the steps involved in "running".
- For a function that takes arguments `peer1` and `peer2`, explain the difference between the two.
- For a function that takes an argument `height`, either explain in the comment what this is the _height of_. Alternatively, expand the variable name to remove the ambiguity.
- For a test, document what it is meant to test, and why the expected answers are, in fact, expected.

### Changing Code Instead of Comments

Keep in mind that better variable names can reduce the need for comments, e.g.:

- `burnblock_height` instead of `height` may eliminate the need to comment that `height` refers to a burnblock height
- `process_microblocks` instead of `process_blocks` is more correct, and may eliminate the need to explain that the inputs are microblocks
- `add_transaction_to_microblock` explains more than `handle_transaction`, and reduces the need to even read the comment

# Licensing and contributor license agreement

`stacks-core` is released under the terms of the GPL version 3. Contributions
that are not licensed under compatible terms will be rejected. Moreover,
contributions will not be accepted unless _all_ authors accept the project's
contributor license agreement.

## Use of AI-code Generation

The Stacks Foundation has a very strict policy of not accepting AI-generated code PRs due to uncertainly about licensing issues.
