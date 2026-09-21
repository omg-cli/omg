---
title: Documentation style
sidebar_position: 97
description: How to write OMG documentation that a first-time computer user can follow
---

# Documentation style

This page is for people who write OMG documentation. It keeps every page in the same
plain, careful voice, so a reader who has never used a computer can still follow it.

Technical accuracy comes first. A page that reads well but tells the reader to run a
command that does not exist is worse than a page that is hard to read.

## The one rule that matters most

**Never describe something you have not checked.** Commands, options, file names,
configuration keys, and defaults must come from the code or from the program itself:

```bash
# The command definitions are the source of truth
src/cli/args.rs

# What the program actually accepts (run this in your checkout)
omg <command> --help
omg --all-commands --help
```

If you cannot check a claim, write it as an open question instead of a fact.

## Keep the cautions

OMG documentation records real limits: which systems are supported, what a command does
not do, and what a report does not prove. **Reword those cautions, never remove them.**
Deleting a caution is a factual error, not a style improvement.

## Write for someone who has never used a computer

Assume the reader:

- does not know what a terminal, a shell, a PATH, or a package manager is;
- does not know which operating system the machine runs;
- reads one sentence at a time and gives up on long sentences;
- copies commands exactly, so every command must be correct and complete.

Rules that follow from that:

1. **Say what the page is for in the first three sentences**, without jargon.
2. **Explain a term the first time you use it.** Link to [the glossary](./glossary.md)
   instead of repeating long explanations.
3. **Keep sentences short.** One idea per sentence. Write "Do X. Then do Y." instead of
   one sentence with three clauses.
4. **Address the reader as "you"**, and say what they should see after each step.
5. **Number the steps when order matters**, and show one step per code block.
6. **Put a warning before a step that changes the computer**, not after it.
7. **Avoid marketing words** such as "blazing", "seamless", or "revolutionary". Describe
   what happens instead.
8. **Do not use symbols without explaining them.** If you write `$HOME` or
   `$XDG_RUNTIME_DIR`, say what it stands for in this context.
9. **Prefer a short table or list** over a long paragraph.
10. **End the page with where to go next** and how to ask for help.

## Page shape used across these docs

```markdown
---
title: <short title>
sidebar_position: <number>
description: <one plain sentence>
---

# <Title>

<In plain words: two to four sentences about what this page helps you do.>

## What you need first

- <software, permission, or information the reader must already have>

## <Steps or topics, numbered when order matters>

1. **Step name.** What you do, then what you should see.

   ```bash
   omg <command> [options]
   ```

2. **Next step.** ...

## If something goes wrong

| What you see | What it means | What to do |
| --- | --- | --- |

## Where to go next

- [Related page](./related.md)
```

## Words to prefer

| Instead of | Write |
| --- | --- |
| invoke the binary | run the command |
| leverage, utilize | use |
| deprecate | will be removed in a future version |
| non-interactive | you will not be asked to confirm anything |
| idempotent | you can run it again safely |
| dependency | another package this package needs |
| backend | the package system for your operating system |

## Before you commit a documentation change

- [ ] Every command and option in the page exists in `src/cli/args.rs` or in `--help`.
- [ ] Every file path and configuration key in the page exists in the code.
- [ ] No caution, limit, or "this does not do X" sentence was deleted.
- [ ] Frontmatter (`title`, `sidebar_position`, `description`) is present and accurate.
- [ ] The page follows the shape above and links to the glossary for jargon.
- [ ] The file uses LF line endings, ends with one newline, and has no trailing spaces.
- [ ] Headings are in order, code fences are closed, and tables have a header row.

## See also

- [Glossary](./glossary.md) — plain-language definitions of words used in these docs.
- [Getting started](./getting-started.md) — the beginner walkthrough these rules serve.
