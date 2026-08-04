#!/usr/bin/env python3
"""Recover the candidate accepted by the unique non-decoy audit rule."""

import ast
from pathlib import Path


CHALLENGE = Path(__file__).resolve().parents[1] / "challenge" / "audit_blob.py"


def find_signal_rule(tree: ast.Module) -> tuple[list[int], int]:
    """Return the long reference and final accumulator from the unique real rule."""
    matches = []

    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or not node.name.startswith("audit_rule_"):
            continue

        references = [
            statement.value
            for statement in node.body
            if isinstance(statement, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "reference" for target in statement.targets)
            and isinstance(statement.value, ast.List)
        ]
        if len(references) != 1:
            continue

        reference = ast.literal_eval(references[0])
        if len(reference) <= 4:
            continue

        returns = [item for item in ast.walk(node) if isinstance(item, ast.Return)]
        final_values = []
        for item in returns:
            value = item.value
            if (
                isinstance(value, ast.Compare)
                and isinstance(value.left, ast.Name)
                and value.left.id == "acc"
                and len(value.comparators) == 1
                and isinstance(value.comparators[0], ast.Constant)
            ):
                final_values.append(value.comparators[0].value)

        if len(final_values) == 1:
            matches.append((reference, final_values[0]))

    if len(matches) != 1:
        raise RuntimeError(f"expected one signal rule, found {len(matches)}")

    return matches[0]


def recover(reference: list[int], final_acc: int) -> str:
    # State is small after restricting candidates to printable ASCII. Keep all
    # surviving paths so the final accumulator check resolves any ambiguity.
    states: list[tuple[int, bytes]] = [(0x5A, b"")]

    for index, target in enumerate(reference):
        next_states = []
        for previous, prefix in states:
            for char in range(0x20, 0x7F):
                current = ((previous * 33) ^ char ^ index) & 0xFF
                if ((char + current + index * 7) & 0xFF) == target:
                    next_states.append((current, prefix + bytes([char])))
        states = next_states

    answers = [candidate.decode() for acc, candidate in states if acc == final_acc]
    if len(answers) != 1:
        raise RuntimeError(f"expected one candidate, found {len(answers)}")
    return answers[0]


def main() -> None:
    tree = ast.parse(CHALLENGE.read_text())
    reference, final_acc = find_signal_rule(tree)
    print(recover(reference, final_acc))


if __name__ == "__main__":
    main()
