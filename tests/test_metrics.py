from ida_bridge.metrics import analyze_body, _sanitize


class TestAnalyzeBody:
    def test_empty(self):
        r = analyze_body("")
        assert r["logic_lines"] == 0
        assert r["branch_density"] == 0

    def test_control_flow(self):
        body = "if (x > 0) {\n    return x;\n}\nreturn 0;\n"
        r = analyze_body(body)
        assert r["logic_lines"] == 3
        assert r["branch_density"] == 1.0

    def test_call_detection(self):
        r = analyze_body("result = decrypt_aes(key, data);")
        assert r["call_density"] == 1.0

    def test_string_detection(self):
        r = analyze_body('printf("hello");')
        assert r["string_density"] == 1.0

    def test_opaque_refs(self):
        r = analyze_body("x = byte_1A2B + unk_CAFE;")
        assert r["opaque_density"] == 2.0

    def test_decl_lines_skipped(self):
        r = analyze_body("int x;\nunsigned int y;\nx = 1;\n")
        assert r["logic_lines"] == 1


class TestSanitize:
    def test_illegal_chars(self):
        assert _sanitize("foo<bar>") == "foo_bar_"

    def test_truncate(self):
        assert len(_sanitize("a" * 300)) == 200

    def test_custom_maxlen(self):
        assert len(_sanitize("a" * 50, maxlen=10)) == 10

    def test_clean_name(self):
        assert _sanitize("_add") == "_add"
