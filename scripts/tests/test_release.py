import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from zipfile import ZipFile

from scripts import release


DEPLOYMENT_ID = "28570f16-da32-4c14-bd2e-c1acc0782365"


class ReleaseRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "target").mkdir()
        (self.root / "pom.xml").write_bytes(b"release pom")
        self.files = [b"release pom", b"jar", b"sources", b"javadoc"]
        for suffix, body in zip((".jar", "-sources.jar", "-javadoc.jar"), self.files[1:]):
            (self.root / "target" / f"xmldsig-1.2.3{suffix}").write_bytes(body)
        (self.root / "target" / "xmldsig-1.2.3.pom").write_bytes(self.files[0])
        for name in release.artifact_names("1.2.3"):
            (self.root / "target" / (name + ".asc")).write_bytes(b"test signature")
        release.prepare_release("1.2.3", "1770000000", self.root)
        request = patch("scripts.release.request_bytes")
        deploy = patch("scripts.release.upload_release", return_value=DEPLOYMENT_ID)
        wait = patch("scripts.release.wait_for_publication")
        self.request = request.start()
        self.deploy = deploy.start()
        self.wait = wait.start()
        self.addCleanup(request.stop)
        self.addCleanup(deploy.stop)
        self.addCleanup(wait.stop)

    def run_release(self, **options):
        return release.publish_or_resume("1.2.3", "1770000000", root=self.root, **options)

    def status(self, state, **extra):
        return json.dumps({"deploymentId": DEPLOYMENT_ID, "deploymentState": state, **extra}).encode()

    def test_new_release_uploads_once(self):
        self.request.return_value = None
        self.run_release(tag_existed=False)
        self.deploy.assert_called_once_with(
            "1.2.3", release.verified_files("1.2.3", "1770000000", self.root),
        )
        self.wait.assert_called_once_with(DEPLOYMENT_ID, "1.2.3")

    def test_existing_tag_and_repository_404_never_replay_upload(self):
        self.request.return_value = None
        with self.assertRaisesRegex(release.ReleaseError, "does not prove"):
            self.run_release(tag_existed=True)
        self.deploy.assert_not_called()

    def test_explicit_retry_can_recover_failure_before_upload(self):
        self.request.return_value = None
        self.run_release(tag_existed=True, retry_upload=True)
        self.deploy.assert_called_once()

    def test_published_identical_artifacts_skip_upload(self):
        self.request.side_effect = self.files
        self.assertIn("already published", self.run_release(tag_existed=True))
        self.deploy.assert_not_called()

    def test_different_pom_prevents_reuse(self):
        self.request.return_value = b"another release"
        with self.assertRaisesRegex(release.ReleaseError, "POM differs"):
            self.run_release(tag_existed=True, retry_upload=True)
        self.deploy.assert_not_called()

    def test_different_jar_prevents_reuse(self):
        self.request.side_effect = [self.files[0], b"foreign jar"]
        with self.assertRaisesRegex(release.ReleaseError, "differs"):
            self.run_release(tag_existed=True)
        self.deploy.assert_not_called()

    def test_partial_repository_propagation_does_not_upload(self):
        self.request.side_effect = [self.files[0], None]
        with self.assertRaisesRegex(release.ReleaseError, "not all visible"):
            self.run_release(tag_existed=True, retry_upload=True)
        self.deploy.assert_not_called()

    def test_nonpublished_deployment_states_never_upload(self):
        for state in ("PENDING", "VALIDATING", "VALIDATED", "PUBLISHING", "FAILED"):
            with self.subTest(state=state):
                self.request.reset_mock()
                self.request.return_value = self.status(state, purls=[])
                with self.assertRaisesRegex(release.ReleaseError, state):
                    self.run_release(tag_existed=True, deployment_id=DEPLOYMENT_ID)
                self.request.assert_called_once()
                self.deploy.assert_not_called()

    def test_published_deployment_with_repository_404_does_not_upload(self):
        self.request.side_effect = [self.status("PUBLISHED"), None]
        with self.assertRaisesRegex(release.ReleaseError, "not propagated"):
            self.run_release(tag_existed=True, deployment_id=DEPLOYMENT_ID)
        self.deploy.assert_not_called()

    def test_published_deployment_and_matching_artifacts_complete(self):
        self.request.side_effect = [self.status("PUBLISHED", purls=["pkg:maven/io.github.robsonkades/xmldsig@1.2.3"]), *self.files]
        self.assertIn("already published", self.run_release(tag_existed=True, deployment_id=DEPLOYMENT_ID))
        self.deploy.assert_not_called()

    def test_deployment_status_and_upload_override_cannot_be_combined(self):
        with self.assertRaisesRegex(release.ReleaseError, "not both"):
            self.run_release(tag_existed=True, deployment_id=DEPLOYMENT_ID, retry_upload=True)
        self.request.assert_not_called()
        self.deploy.assert_not_called()

    def test_untrusted_status_responses_fail_closed(self):
        responses = [b"not json", b"[]", b"{}", self.status("UNKNOWN"),
                     self.status("PUBLISHED", purls=["pkg:maven/other/project@1.2.3"]),
                     self.status("PENDING", purls="bad shape")]
        for response in responses:
            with self.subTest(response=response):
                self.request.return_value = response
                with self.assertRaises(release.ReleaseError):
                    self.run_release(tag_existed=True, deployment_id=DEPLOYMENT_ID)
                self.deploy.assert_not_called()

    def test_invalid_deployment_id_never_reaches_network(self):
        with self.assertRaisesRegex(release.ReleaseError, "UUID"):
            self.run_release(tag_existed=True, deployment_id="../other")
        self.request.assert_not_called()
        self.deploy.assert_not_called()

    def test_unconfirmed_remote_state_cannot_be_overridden(self):
        self.request.side_effect = release.ReleaseError("HTTP 503")
        with self.assertRaisesRegex(release.ReleaseError, "503"):
            self.run_release(tag_existed=True, retry_upload=True)
        self.deploy.assert_not_called()

    def test_invalid_version_and_timestamp_never_reach_network(self):
        for version, timestamp in (("1.2.3-SNAPSHOT", "1"), ("../other", "1"), ("1.2.3", "bad")):
            with self.subTest(version=version, timestamp=timestamp):
                with self.assertRaises(release.ReleaseError):
                    release.publish_or_resume(version, timestamp, False)
        self.request.assert_not_called()
        self.deploy.assert_not_called()

    def test_cli_publishing_failure_is_nonzero_and_preserves_recovery_guidance(self):
        with patch("scripts.release.publish_or_resume", side_effect=release.ReleaseError("Preserve deployment ID for recovery")):
            error = io.StringIO()
            with contextlib.redirect_stderr(error):
                code = release.main(["--version", "1.2.3", "--timestamp", "1", "--tag-existed", "false"])
        self.assertEqual(1, code)
        self.assertIn("deployment ID", error.getvalue())

    def test_cli_publication_requires_explicit_tag_state(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                release.main(["--version", "1.2.3", "--timestamp", "1"])
        self.assertEqual(2, caught.exception.code)
        self.request.assert_not_called()
        self.deploy.assert_not_called()

    def test_changed_build_outputs_cannot_replace_the_verified_upload(self):
        (self.root / "target" / "xmldsig-1.2.3.jar").write_bytes(b"rebuilt unverified jar")
        (self.root / "pom.xml").write_bytes(b"changed pom")
        self.request.return_value = None
        self.run_release(tag_existed=False)
        uploaded = self.deploy.call_args.args[1]
        self.assertEqual(b"jar", uploaded["xmldsig-1.2.3.jar"])
        self.assertEqual(b"release pom", uploaded["xmldsig-1.2.3.pom"])

    def test_modified_verified_artifact_stops_before_network(self):
        (self.root / "target" / "verified-release" / "xmldsig-1.2.3.jar").write_bytes(b"tampered")
        with self.assertRaisesRegex(release.ReleaseError, "changed after verification"):
            self.run_release(tag_existed=False)
        self.request.assert_not_called()
        self.deploy.assert_not_called()

    def test_upload_failure_or_wait_failure_never_replays_upload(self):
        self.request.return_value = None
        self.wait.side_effect = release.ReleaseError("Timed out; preserve deployment ID")
        with self.assertRaisesRegex(release.ReleaseError, "deployment ID"):
            self.run_release(tag_existed=False)
        self.deploy.assert_called_once()

    def test_snapshot_cannot_be_silently_overwritten(self):
        with self.assertRaises(FileExistsError):
            release.prepare_release("1.2.3", "1770000000", self.root)

    def test_missing_signature_prevents_preparation(self):
        (self.root / "target" / "xmldsig-1.2.3.jar.asc").unlink()
        with self.assertRaises(FileNotFoundError):
            release.prepare_release("1.2.3", "1770000000", self.root)

    def test_bundle_contains_exact_verified_bytes_signatures_and_checksums(self):
        files = release.verified_files("1.2.3", "1770000000", self.root)
        with ZipFile(io.BytesIO(release.release_bundle("1.2.3", files))) as bundle:
            prefix = "io/github/robsonkades/xmldsig/1.2.3/"
            self.assertEqual(24, len(bundle.namelist()))
            for name, body in files.items():
                self.assertEqual(body, bundle.read(prefix + name))
                if not name.endswith(".asc"):
                    for algorithm in ("md5", "sha1", "sha256", "sha512"):
                        expected = hashlib.new(algorithm, body, usedforsecurity=False).hexdigest().encode()
                        self.assertEqual(expected, bundle.read(prefix + name + "." + algorithm))

    def test_untrusted_manifest_never_supplies_file_paths(self):
        stage = self.root / "target" / "verified-release"
        manifest = json.loads((stage / "manifest.json").read_text())
        manifest["sha256"]["../../pom.xml"] = "fake hash"
        (stage / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(release.ReleaseError, "unexpected artifact set"):
            self.run_release(tag_existed=False)
        self.request.assert_not_called()


class UploadTest(unittest.TestCase):
    def test_upload_uses_the_documented_multipart_format_once(self):
        with patch("scripts.release.request_bytes", return_value=DEPLOYMENT_ID.encode()) as request:
            self.assertEqual(DEPLOYMENT_ID, release.upload_release("1.2.3", {"xmldsig-1.2.3.jar": b"verified"}))
        request.assert_called_once()
        self.assertIn("publishingType=AUTOMATIC", request.call_args.args[0])
        options = request.call_args.kwargs
        self.assertTrue(options["portal"])
        boundary = options["content_type"].split("boundary=")[1].encode()
        self.assertTrue(options["data"].startswith(b"--" + boundary + b"\r\n"))
        self.assertTrue(options["data"].endswith(b"\r\n--" + boundary + b"--\r\n"))
        header, zipped = options["data"].split(b"\r\n\r\n", 1)
        self.assertIn(b'name="bundle"; filename="central-bundle.zip"', header)
        zipped = zipped.rsplit(b"\r\n--" + boundary, 1)[0]
        with ZipFile(io.BytesIO(zipped)) as bundle:
            self.assertEqual(b"verified", bundle.read("io/github/robsonkades/xmldsig/1.2.3/xmldsig-1.2.3.jar"))

    def test_uncertain_upload_is_never_retried(self):
        for outcome in (release.ReleaseError("private failure"), b"invalid UUID", b"\xff"):
            with self.subTest(outcome=outcome):
                with patch("scripts.release.request_bytes") as request:
                    if isinstance(outcome, Exception):
                        request.side_effect = outcome
                    else:
                        request.return_value = outcome
                    with self.assertRaisesRegex(release.ReleaseError, "Check the Portal") as caught:
                        release.upload_release("1.2.3", {})
                    request.assert_called_once()
                    self.assertNotIn("private", str(caught.exception))

    def test_polling_only_rechecks_status_until_published(self):
        with patch("scripts.release.deployment_state", side_effect=["PENDING", "PUBLISHING", "PUBLISHED"]) as status:
            with patch("scripts.release.time.sleep"):
                release.wait_for_publication(DEPLOYMENT_ID, "1.2.3")
        self.assertEqual(3, status.call_count)

    def test_terminal_and_uncertain_status_preserve_deployment_id(self):
        for state in ("FAILED", "VALIDATED", release.ReleaseError("HTTP 503")):
            with self.subTest(state=state):
                with patch("scripts.release.deployment_state") as status:
                    if isinstance(state, Exception):
                        status.side_effect = state
                    else:
                        status.return_value = state
                    with self.assertRaisesRegex(release.ReleaseError, DEPLOYMENT_ID):
                        release.wait_for_publication(DEPLOYMENT_ID, "1.2.3")
                    status.assert_called_once()

    def test_publication_deadline_stops_without_further_requests(self):
        with patch("scripts.release.time.monotonic", side_effect=[0, 601]):
            with patch("scripts.release.deployment_state") as status:
                with self.assertRaisesRegex(release.ReleaseError, "Timed out.*" + DEPLOYMENT_ID):
                    release.wait_for_publication(DEPLOYMENT_ID, "1.2.3")
                status.assert_not_called()


class CentralTransportTest(unittest.TestCase):
    def setUp(self):
        opener = patch("scripts.release.build_opener")
        self.opener = opener.start().return_value
        self.addCleanup(opener.stop)

    def test_status_uses_documented_post_bearer_and_bounded_timeout(self):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b"{}"
        self.opener.open.return_value = response
        with patch.dict("os.environ", {"CENTRAL_USERNAME": "test-user", "CENTRAL_PASSWORD": "test-pass"}):
            release.request_bytes("https://central.sonatype.com/api/v1/publisher/status?id=test", portal=True)
        request = self.opener.open.call_args.args[0]
        self.assertEqual("POST", request.method)
        expected = base64.b64encode(b"test-user:test-pass").decode()
        self.assertEqual(f"Bearer {expected}", request.get_header("Authorization"))
        self.assertEqual(30, self.opener.open.call_args.kwargs["timeout"])

    def test_public_repository_404_is_absence_but_portal_404_is_an_error(self):
        self.opener.open.side_effect = HTTPError("https://example.invalid", 404, "not found", {}, None)
        self.assertIsNone(release.request_bytes("https://repo.maven.apache.org/example"))
        with patch.dict("os.environ", {"CENTRAL_USERNAME": "test-user", "CENTRAL_PASSWORD": "test-pass"}):
            with self.assertRaisesRegex(release.ReleaseError, "HTTP 404"):
                release.request_bytes("https://central.sonatype.com/example", portal=True)

    def test_public_request_has_no_credentials(self):
        with patch.dict("os.environ", {"CENTRAL_USERNAME": "test-user", "CENTRAL_PASSWORD": "test-pass"}):
            release.request_bytes("https://repo.maven.apache.org/example")
        self.assertIsNone(self.opener.open.call_args.args[0].get_header("Authorization"))

    def test_http_and_network_errors_are_not_retried_or_leaked(self):
        errors = [HTTPError("https://example.invalid", 503, "private response", {}, None),
                  URLError("private connection details"), TimeoutError("private details")]
        for error in errors:
            with self.subTest(error=type(error)):
                self.opener.open.reset_mock()
                self.opener.open.side_effect = error
                with self.assertRaises(release.ReleaseError) as caught:
                    release.request_bytes("https://repo.maven.apache.org/example")
                self.assertNotIn("private", str(caught.exception))
                self.opener.open.assert_called_once()

    def test_missing_credentials_stop_before_request(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(release.ReleaseError, "credentials"):
                release.request_bytes("https://central.sonatype.com/example", portal=True)
        self.opener.open.assert_not_called()

    def test_redirects_cannot_forward_authorization(self):
        self.assertIsNone(release.NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.invalid"))


class ReleaseRefPolicyTest(unittest.TestCase):
    def test_master_and_matching_tag_are_allowed_without_network_or_secrets(self):
        with patch("scripts.release.request_bytes") as request, patch.dict("os.environ", {}, clear=True):
            for version in ("1.2.3", "1.2.3-RC1"):
                for ref in ("refs/heads/master", f"refs/tags/v{version}"):
                    with self.subTest(version=version, ref=ref), contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(0, release.main(["--version", version, "--validate-ref", ref]))
            request.assert_not_called()

    def test_other_branches_and_mismatched_tags_fail_closed(self):
        refs = ("refs/heads/feature", "refs/heads/master-evil", "refs/tags/v9.9.9", "refs/pull/1/merge", "", "master")
        for ref in refs:
            with self.subTest(ref=ref), contextlib.redirect_stderr(io.StringIO()) as errors:
                self.assertEqual(1, release.main(["--version", "1.2.3", "--validate-ref", ref]))
                self.assertIn("matching version tag", errors.getvalue())

    def test_invalid_versions_fail_even_on_master(self):
        for version in ("1.2.3-SNAPSHOT", "../1.2.3", "1.2.3;echo injected", ""):
            with self.subTest(version=version), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(1, release.main(["--version", version, "--validate-ref", "refs/heads/master"]))

    def test_artifact_modes_still_require_a_timestamp(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            release.main(["--version", "1.2.3", "--check"])
        self.assertEqual(2, error.exception.code)


if __name__ == "__main__":
    unittest.main()
