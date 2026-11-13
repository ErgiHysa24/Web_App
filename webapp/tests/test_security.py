import pytest

from watchdog_web.security import SecretBox, hash_password, hash_token, new_api_token, password_problem, verify_password


def test_password_hash_roundtrip():
    h = hash_password("una password lunga")
    assert h.startswith("scrypt$") and "una password" not in h
    assert verify_password("una password lunga", h)
    assert not verify_password("un'altra", h)
    assert not verify_password("x", "formato-sbagliato")
    assert hash_password("una password lunga") != h          # sale diverso ogni volta


def test_password_rules():
    assert password_problem("corta") is not None
    assert password_problem("aaaaaaaaaaaaaa") is not None
    assert password_problem("mario-password-1", "mario") is not None
    assert password_problem("Prova-Sicura-2026", "mario") is None
    assert password_problem("Breve-2026", "mario") is not None              # meno di 12 caratteri
    assert password_problem("La-Mia-Password-1", "mario") is not None       # parola ovvia
    assert password_problem("watchdog-del-lab", "mario") is not None


def test_secret_box_needs_the_same_key():
    box = SecretBox("a" * 40)
    enc = box.encrypt("password-ssh")
    assert "password-ssh" not in enc and box.decrypt(enc) == "password-ssh"
    assert box.encrypt("") == "" and box.decrypt("") == ""
    with pytest.raises(ValueError):
        SecretBox("b" * 40).decrypt(enc)


def test_api_token_is_stored_only_as_hash():
    token, prefix, digest = new_api_token()
    assert token.startswith("wd_") and token.startswith(prefix)
    assert digest == hash_token(token) and token not in digest
