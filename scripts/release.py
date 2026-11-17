"""Conservative Central release recovery; importing this module has no side effects."""

import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import UUID, uuid4
from zipfile import ZIP_DEFLATED, ZipFile


ARTIFACT_SUFFIXES = (".pom", ".jar", "-sources.jar", "-javadoc.jar")


class ReleaseError(Exception):
    """The remote state is not sufficient to safely continue the release."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # In particular, never forward a Portal authorization header to another location.
        return None


def request_bytes(url, *, portal=False, data=None, content_type=None):
    headers = {}
    if portal:
        username = os.environ.get("CENTRAL_USERNAME")
        password = os.environ.get("CENTRAL_PASSWORD")
        if not username or not password:
            raise ReleaseError("Central credentials are required for the Publisher API.")
        token = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        headers["Authorization"] = f"Bearer {token}"
    if content_type:
        headers["Content-Type"] = content_type
    request = Request(url, data=data, headers=headers, method="POST" if portal else "GET")
    try:
        with build_opener(NoRedirect()).open(request, timeout=30) as response:
            return response.read()
    except HTTPError as error:
        if error.code == 404 and not portal:
            return None
        raise ReleaseError(f"Cannot confirm Central state (HTTP {error.code}).") from None
    except (URLError, TimeoutError, OSError):
        raise ReleaseError("Cannot confirm Central state. Check the Portal before retrying.") from None


def deployment_state(deployment_id, version):
    # https://central.sonatype.org/publish/publish-portal-api/#verify-status-of-the-deployment
    try:
        deployment_id = str(UUID(deployment_id))
    except ValueError:
        raise ReleaseError("deployment_id must be a Central deployment UUID.") from None
    body = request_bytes(
        f"https://central.sonatype.com/api/v1/publisher/status?id={deployment_id}", portal=True
    )
    try:
        status = json.loads(body)
    except (ValueError, TypeError):
        raise ReleaseError("Central returned an unreadable deployment status.") from None
    if not isinstance(status, dict) or status.get("deploymentId") != deployment_id:
        raise ReleaseError("Central returned a different deployment ID.")
    purls = status.get("purls")
    expected = f"pkg:maven/io.github.robsonkades/xmldsig@{version}"
    if purls is not None and not isinstance(purls, list):
        raise ReleaseError("Central returned unreadable deployment coordinates.")
    if purls and expected not in purls:
        raise ReleaseError("The deployment does not identify this library version.")
    state = status.get("deploymentState")
    if state not in {"PENDING", "VALIDATING", "VALIDATED", "PUBLISHING", "PUBLISHED", "FAILED"}:
        raise ReleaseError("Central returned an unknown deployment state.")
    return state


def validate_release(version, timestamp):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?", version) or "SNAPSHOT" in version.upper():
        raise ReleaseError("Expected a release version such as 1.1.0 or 1.1.0-RC1.")
    if not re.fullmatch(r"[0-9]+", timestamp):
        raise ReleaseError("The release commit timestamp must be an unsigned integer.")


def validate_release_ref(version, ref):
    """Authorize a new release from master, or recovery of this exact version's tag."""
    validate_release(version, "0")
    if ref not in {"refs/heads/master", f"refs/tags/v{version}"}:
        raise ReleaseError("Release must run from master or the matching version tag.")


def artifact_names(version):
    return [f"xmldsig-{version}{suffix}" for suffix in ARTIFACT_SUFFIXES]


def prepare_release(version, timestamp, root=Path(".")):
    """Capture the files produced by `mvn -Prelease clean verify`, without rebuilding."""
    validate_release(version, timestamp)
    names = artifact_names(version)
    names += [name + ".asc" for name in names]
    # GPG plugin 3.2.6 copies the signed POM into target with the final artifact name.
    files = {name: (root / "target" / name).read_bytes() for name in names}
    if files[f"xmldsig-{version}.pom"] != (root / "pom.xml").read_bytes():
        raise ReleaseError("The signed POM differs from the release revision.")
    if any(not body for body in files.values()):
        raise ReleaseError("A verified artifact or signature is empty.")
    stage = root / "target" / "verified-release"
    stage.mkdir()  # Never silently replace an earlier verified snapshot.
    for name, body in files.items():
        (stage / name).write_bytes(body)
    manifest = {"version": version, "timestamp": timestamp,
                "sha256": {name: hashlib.sha256(body).hexdigest() for name, body in files.items()}}
    (stage / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return "Captured signed release artifacts and SHA-256 hashes in target/verified-release."


def verified_files(version, timestamp, root=Path(".")):
    validate_release(version, timestamp)
    stage = root / "target" / "verified-release"
    try:
        manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    except (ValueError, OSError):
        raise ReleaseError("Missing or unreadable verified release manifest; run --prepare after clean verify.") from None
    if not isinstance(manifest, dict) or manifest.get("version") != version or manifest.get("timestamp") != timestamp:
        raise ReleaseError("The verified release manifest identifies another release.")
    names = artifact_names(version)
    names += [name + ".asc" for name in names]
    hashes = manifest.get("sha256")
    if not isinstance(hashes, dict) or set(hashes) != set(names):
        raise ReleaseError("The verified release manifest has an unexpected artifact set.")
    files = {}
    for name in names:
        body = (stage / name).read_bytes()
        if hashlib.sha256(body).hexdigest() != hashes[name]:
            raise ReleaseError(f"Verified artifact changed after verification: {name}.")
        files[name] = body
    return files


def release_bundle(version, files):
    # https://central.sonatype.org/publish/publish-portal-upload/
    buffer = io.BytesIO()
    prefix = f"io/github/robsonkades/xmldsig/{version}/"
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as bundle:
        for name, body in files.items():
            bundle.writestr(prefix + name, body)
            if not name.endswith(".asc"):
                for algorithm in ("md5", "sha1", "sha256", "sha512"):
                    checksum = hashlib.new(algorithm, body, usedforsecurity=False).hexdigest()
                    bundle.writestr(prefix + name + "." + algorithm, checksum)
    return buffer.getvalue()


def upload_release(version, files):
    # Upload exactly once. An ambiguous transport failure must never replay the POST.
    boundary = "xmldsig-" + uuid4().hex
    body = (f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="bundle"; filename="central-bundle.zip"\r\n'
            "Content-Type: application/octet-stream\r\n\r\n").encode()
    body += release_bundle(version, files) + f"\r\n--{boundary}--\r\n".encode()
    try:
        response = request_bytes(
            f"https://central.sonatype.com/api/v1/publisher/upload?name=xmldsig-{version}&publishingType=AUTOMATIC",
            portal=True, data=body, content_type=f"multipart/form-data; boundary={boundary}",
        )
        deployment_id = str(UUID(response.decode("ascii").strip()))
    except (ReleaseError, ValueError, AttributeError):
        raise ReleaseError("Upload outcome is uncertain. Check the Portal for a deployment ID before retrying; "
                           "no automatic upload retry was attempted.") from None
    print(f"Central deployment ID: {deployment_id}", flush=True)
    return deployment_id


def wait_for_publication(deployment_id, version, timeout=600):
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            state = deployment_state(deployment_id, version)
            if state == "PUBLISHED":
                return
            if state in {"FAILED", "VALIDATED"}:
                raise ReleaseError(f"Deployment {state}; inspect the Portal.")
            time.sleep(min(5, max(0, deadline - time.monotonic())))
        raise ReleaseError("Timed out waiting for publication.")
    except ReleaseError as error:
        raise ReleaseError(f"{error} Preserve deployment ID {deployment_id} and resume with --deployment-id; "
                           "no new upload was attempted.") from None


def publish_or_resume(version, timestamp, tag_existed, deployment_id="", retry_upload=False, root=Path(".")):
    validate_release(version, timestamp)
    if deployment_id and retry_upload:
        raise ReleaseError("Use deployment_id to resume an existing upload, or retry_upload after checking the Portal; not both.")

    files = verified_files(version, timestamp, root)

    state = deployment_state(deployment_id, version) if deployment_id else None
    if state and state != "PUBLISHED":
        if state == "FAILED":
            raise ReleaseError("Deployment FAILED. Inspect the Portal errors; no new upload was attempted.")
        if state == "VALIDATED":
            raise ReleaseError("Deployment VALIDATED and awaits publication in the Portal; no new upload was attempted.")
        raise ReleaseError(f"Deployment {state}. Resume with the same deployment_id later; no new upload was attempted.")

    artifact = f"xmldsig-{version}"
    repository = f"https://repo.maven.apache.org/maven2/io/github/robsonkades/xmldsig/{version}"
    pom = request_bytes(f"{repository}/{artifact}.pom")
    if pom is not None:
        if pom != files[f"{artifact}.pom"]:
            raise ReleaseError("The published POM differs from this release revision.")
        for suffix in (".jar", "-sources.jar", "-javadoc.jar"):
            content = request_bytes(f"{repository}/{artifact}{suffix}")
            if content is None:
                raise ReleaseError("Published artifacts are not all visible yet. Retry later; no upload was attempted.")
            if content != files[f"{artifact}{suffix}"]:
                raise ReleaseError(f"The published {artifact}{suffix} differs from the verified artifact.")
        return "The exact release is already published; resume GitHub Release creation."

    if state == "PUBLISHED":
        raise ReleaseError("Deployment PUBLISHED, but the repository has not propagated it yet. Retry later; no upload was attempted.")
    if tag_existed and not retry_upload:
        raise ReleaseError(
            "The release tag already exists and Central returned 404. This does not prove that no upload exists. "
            "Supply deployment_id from the previous release log/Portal, or set retry_upload only after confirming "
            "that no deployment for this version is active or published. No upload was attempted."
        )
    uploaded_id = upload_release(version, files)
    wait_for_publication(uploaded_id, version)
    return "Central published the verified release artifacts."


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--timestamp")
    parser.add_argument("--tag-existed", choices=("true", "false"))
    parser.add_argument("--deployment-id", default="")
    parser.add_argument("--retry-upload", default="false", choices=("true", "false"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--validate-ref", metavar="REF", help="Check the workflow source ref offline, before accessing release secrets.")
    mode.add_argument("--prepare", action="store_true", help="Capture signed artifacts after clean verify; no network.")
    mode.add_argument("--check", action="store_true", help="Check the captured artifact hashes; no network.")
    args = parser.parse_args(argv)
    if args.validate_ref is None:
        if args.timestamp is None:
            parser.error("--timestamp is required for release artifacts")
        if not args.prepare and not args.check and args.tag_existed is None:
            parser.error("--tag-existed is required for publication")
    try:
        if args.validate_ref is not None:
            validate_release_ref(args.version, args.validate_ref)
            print("Release source ref is allowed.")
            return 0
        if args.prepare:
            print(prepare_release(args.version, args.timestamp))
            return 0
        if args.check:
            verified_files(args.version, args.timestamp)
            print("Verified release artifact hashes match.")
            return 0
        print(publish_or_resume(args.version, args.timestamp, args.tag_existed == "true",
                                args.deployment_id, args.retry_upload == "true"))
        return 0
    except (ReleaseError, OSError) as error:
        print(f"Release stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
