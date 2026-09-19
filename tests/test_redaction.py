from aegis.executor import redact


def test_redacts_nested_secrets() -> None:
    value = {"token": "secret", "nested": {"Authorization": "Bearer x", "safe": "ok"}}
    assert redact(value) == {
        "token": "[REDACTED]",
        "nested": {"Authorization": "[REDACTED]", "safe": "ok"},
    }


def test_redacts_known_values_in_text_and_dictionary_keys() -> None:
    value = {"echo": "Error: lab-token-user-a", "lab-token-user-a": "Bearer secret-value"}
    assert redact(value, ("lab-token-user-a",)) == {
        "echo": "Error: [REDACTED]",
        "[REDACTED]": "Bearer [REDACTED]",
    }
