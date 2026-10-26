"""桌面端 at-rest 信封（``$wbEncrypted``）导入回归测试。

背景：桌面客户端自 2026-09-24 起把 ``accessToken`` / ``refreshToken``（国内版还有
``nickname`` / ``phoneNumber``）从明文改成
``{"$wbEncrypted": 1, "envelope": base64(...)}`` 信封，framing 为 ``"field"``，
与 ``wb_atrest.seal(key, value, "field")`` 完全同构（换号工具写出来的登录文件也是这个格式）。

修复前的两条故障：
  1. ``credential_crypto.is_encrypted(dict)`` 抛 ``AttributeError`` →
     ``POST /admin/accounts/scan`` 恒 500（整批扫描被一个信封带崩）；
  2. 即便不崩，把信封文本当 token 存进库 → 之后每个请求都 401。
"""

import json

import auth_manager
import credential_crypto
import wb_atrest

KEY = bytes(range(32))


def _sealed(text: str) -> dict:
    return wb_atrest.seal(KEY, text, "field")


def _write_auth_doc(path, access, refresh, nickname, phone, domain="www.workbuddy.cn"):
    doc = {
        "auth": {
            "accessToken": access,
            "refreshToken": refresh,
            "expiresAt": 1_800_000_000_000,
            "refreshExpiresAt": 1_800_000_000_000,
            "domain": domain,
            "sessionState": "sess-1",
        },
        "account": {"uid": "uid-1", "nickname": nickname, "phoneNumber": phone},
    }
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_is_encrypted_ignores_atrest_envelope():
    assert credential_crypto.is_encrypted({"$wbEncrypted": 1, "envelope": "x"}) is False
    assert credential_crypto.is_encrypted(None) is False
    assert credential_crypto.is_encrypted("") is False
    assert credential_crypto.is_encrypted(credential_crypto.PREFIX + "fernet:x") is True


def test_parse_auth_file_decrypts_envelope_fields(tmp_path, monkeypatch):
    monkeypatch.setitem(auth_manager._atrest_state, "key", KEY)
    try:
        doc = _write_auth_doc(
            tmp_path / "enc.info",
            _sealed("tok-at"),
            _sealed("tok-rt"),
            _sealed("昵称"),
            _sealed("13800000000"),
        )
        parsed = auth_manager.parse_auth_file(doc)
        assert parsed is not None
        assert parsed["access_token"] == "tok-at"
        assert parsed["refresh_token"] == "tok-rt"
        assert parsed["nickname"] == "昵称"
        assert parsed["phone"] == "13800000000"
        assert parsed["name"] == "昵称"
        assert parsed["domain"] == "www.workbuddy.cn"
    finally:
        auth_manager._atrest_state["key"] = None


def test_parse_auth_file_keeps_plaintext_docs_working(tmp_path, monkeypatch):
    monkeypatch.setitem(auth_manager._atrest_state, "key", KEY)
    try:
        doc = _write_auth_doc(tmp_path / "plain.info", "plain-at", "plain-rt", "老格式", "13900000000")
        parsed = auth_manager.parse_auth_file(doc)
        assert parsed["access_token"] == "plain-at"
        assert parsed["nickname"] == "老格式"
    finally:
        auth_manager._atrest_state["key"] = None


def test_parse_auth_file_skips_when_key_unavailable(tmp_path, monkeypatch):
    """客户端没在跑 → 拿不到密钥：不抛异常、不返回信封，直接跳过该文件。"""

    class NoKey:
        def is_envelope(self, value):
            return True

        def recover_key(self):
            raise RuntimeError("客户端没在跑")

        def decrypt_field(self, key, value):  # pragma: no cover - 不应被调用
            raise AssertionError("decrypt_field 不应在无密钥时被调用")

    monkeypatch.setattr(auth_manager, "_atrest", lambda: NoKey())
    monkeypatch.setitem(auth_manager._atrest_state, "key", None)
    doc = _write_auth_doc(tmp_path / "nokey.info", _sealed("a"), _sealed("r"), "n", "p")
    assert auth_manager.parse_auth_file(doc) is None
    assert auth_manager._atrest_state["key"] is None


def test_resolve_atrest_fields_passes_plain_values_through(monkeypatch):
    monkeypatch.setitem(auth_manager._atrest_state, "key", KEY)
    try:
        out, err = auth_manager.resolve_atrest_fields({"access_token": "plain", "nickname": ""})
        assert out == {"access_token": "plain", "nickname": ""}
        assert err == ""
    finally:
        auth_manager._atrest_state["key"] = None
