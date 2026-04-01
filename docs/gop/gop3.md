# GOP 3 – Repeated Question Detection in Execution Loop

- **Author:** Gescheit
- **Status:** Accepted
- **Type:** Standards Track
- **Topic:** Core
- **Created:** 2026-03-15
- **Last-Modified:** 2026-03-15

## Abstract

When a device asks the same question repeatedly during command execution (e.g., re-prompting for a password after an incorrect entry), `GenericExecute` keeps answering indefinitely, entering an infinite loop. This GOP introduces detection of consecutive identical questions: if the exact same question text is seen more than a fixed number of times in a row, the execution loop returns an error instead of answering again.

## Motivation

Some commands trigger interactive questions that may repeat if the provided answer is rejected by the device. For example:

```
write  "set master-key\n"
read   "set master-key\r\nEnter the user password:"
write  "mypass\n"                                       <- answer to question
read   "Error: Incorrect password.\r\nEnter the user password:"
write  "mypass\n"                                       <- same answer again
read   "Error: Incorrect password.\r\nEnter the user password:"
...                                                     <- infinite loop
```

The device rejects the answer and re-asks the same question. Since `GenericExecute` has a matching answer configured, it keeps responding. There is no mechanism to detect that the answer was rejected and the question is repeating.

This is distinct from different questions appearing in sequence (which is legitimate — e.g., "Enter password:", then "Confirm password:"). The problem only occurs when the **exact same question text** appears consecutively.

## Goals

- Detect when the same question is asked consecutively more than a threshold number of times.
- Return a `QuestionException` when the threshold is exceeded, breaking the infinite loop.
- Keep the threshold as a constant (currently 2) — the device gets two chances to accept the answer.

## Non-Goals

- Making the repeat threshold configurable per-device or per-command. This can be addressed in a future GOP if needed.
- Changing how answers are matched or selected.
- Handling different-but-similar questions (only exact byte-equal matches count as repeats).

## Proposal

In the question handling branch of `GenericExecute`, the loop tracks the last seen question text. If the newly matched question is byte-equal to the previous one, a counter is incremented. When the counter exceeds the threshold, the loop returns a `QuestionExceptionRepeated` instead of answering again. If the question text differs from the previous one, the counter resets.

### Compatibility

- Commands that legitimately ask the same question twice (e.g., "Enter password:" followed by "Enter password:" for confirmation) will still work — the threshold of 2 allows two identical answers.
- Commands with different sequential questions are unaffected since the counter only tracks consecutive identical questions.
- No API changes. No new options or configuration.

## Rationale

Tracking the last question and comparing by exact bytes is the simplest approach that covers the observed failure mode. Devices that re-ask after a rejected answer always send the same prompt text. Using a small threshold (2) rather than 1 accounts for legitimate cases where the same question appears twice (e.g., password + confirmation).

## Alternatives

1. **Do nothing** — users must set command timeouts and rely on timeout errors, which are slower and less descriptive.
2. **Global question counter** — limit total questions regardless of text. This would break commands that legitimately ask many different questions.
3. **Configurable threshold** — adds API complexity for a rare edge case. Can be added later if needed.

## Testing Plan

Tests are located in `pkg/device/genericcli/gop3_repeated_question_test.go`:

- `TestRepeatedQuestionAborts` — device asks the same question 3 times; execution should fail after the 2nd answer with a `QuestionException`.
- `TestDifferentQuestionsDoNotTriggerLimit` — device asks two different questions sequentially; both are answered normally.
- `TestSameQuestionTwiceIsAllowed` — device asks the same question exactly twice and accepts the answer on the second attempt; execution succeeds.

## References

- `pkg/device/genericcli/genericcli.go` — `GenericExecute`, question handling branch.
- `pkg/device/errors.go` — `QuestionException`.
