from __future__ import annotations

import itertools
import unittest

from kernel.state_machine import (
    InvalidTransition,
    ProposalState,
    Transition,
    allowed_transitions,
    transition,
)


class StateMachinePropertyTests(unittest.TestCase):
    def test_every_state_event_pair_is_explicitly_allowed_or_denied(self) -> None:
        for state, event in itertools.product(ProposalState, Transition):
            if event in allowed_transitions(state):
                self.assertIsInstance(transition(state, event), ProposalState)
            else:
                expected = f"cannot {event.value} from {state.value}"
                with self.assertRaisesRegex(InvalidTransition, expected):
                    transition(state, event)

    def test_terminal_states_have_no_outbound_transitions(self) -> None:
        for state in (
            ProposalState.APPLIED,
            ProposalState.REJECTED,
            ProposalState.INDETERMINATE,
        ):
            self.assertEqual(frozenset(), allowed_transitions(state))


if __name__ == "__main__":
    unittest.main()
