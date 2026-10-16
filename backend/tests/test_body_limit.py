def test_body_limit_blocks_large_json(client):
    big_password = "x" * 5000
    r = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.com", "password": big_password},
    )
    assert r.status_code == 413, r.text


def test_body_limit_does_not_block_multipart_upload(client):
    # The file upload path and multipart/form-data requests are exempt from the global body limit.
    r = client.post(
        "/api/v1/analyze-file/file",
        files={"file": ("hello.txt", b"x" * 5000, "text/plain")},
    )
    assert r.status_code == 401, r.text

