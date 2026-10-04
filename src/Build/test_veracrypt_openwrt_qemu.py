#!/usr/bin/env python3
#
# Copyright (c) 2026 AM Crypto
# Governed by the Apache License 2.0 the full text of which is contained
# in the file License.txt included in VeraCrypt binary and source
# code distribution packages.
#

import argparse
import gzip
import hashlib
import http.server
import io
import lzma
import os
import re
import selectors
import shutil
import socketserver
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path


DEFAULT_OPENWRT_VERSION = "24.10.6"
DEFAULT_TARGET = "x86/64"
DEFAULT_PASSWORD = "OpenWrt-VeraCrypt-Test-Password-123456"
SHELL_PROMPT = ":~#"
PREINSTALLED_PACKAGES = {
    "base-files",
    "busybox",
    "kernel",
    "libc",
    "libgcc1",
    "libpthread",
    "librt",
    "opkg",
}
DEFAULT_RUNTIME_PACKAGES = [
    "bash",
    # OpenWrt emits the FUSE3 library IPK with its ABI suffix; it still
    # Provides: libfuse3.
    "libfuse3-3",
    "fuse3-utils",
    "lvm2",
    "losetup",
    "blkid",
    "mount-utils",
    "kmod-fuse",
    "kmod-loop",
    "kmod-dm",
    "kmod-crypto-misc",
    "veracrypt",
]


class TestError(Exception):
    pass


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class PackageMetadata:
    def __init__(self, path, fields, url=None, source="local"):
        self.path = path
        self.url = url
        self.source = source
        self.package = fields.get("Package", "")
        self.version = fields.get("Version", "")
        self.filename = fields.get("Filename", "")
        self.sha256sum = fields.get("SHA256sum", "")
        self.depends = parse_depends(fields.get("Depends", ""))
        self.provides = parse_name_list(fields.get("Provides", ""))

    def identity(self):
        if self.path:
            return f"local:{self.path.resolve()}"
        return f"remote:{self.url}"

    def display_location(self):
        return str(self.path) if self.path else self.url

    def package_file_name(self):
        if self.path:
            return self.path.name
        url_path = urllib.parse.urlparse(self.url).path
        return Path(url_path).name


class Console:
    def __init__(self, proc, log_path):
        self.proc = proc
        self.selector = selectors.DefaultSelector()
        self.selector.register(proc.stdout, selectors.EVENT_READ)
        os.set_blocking(proc.stdout.fileno(), False)
        self.buffer = ""
        self.log = open(log_path, "w", encoding="utf-8", errors="replace")
        self.command_index = 0

    def close(self):
        self.log.close()

    def _record(self, data):
        text = data.decode("utf-8", errors="replace")
        self.buffer += text
        self.log.write(text)
        self.log.flush()
        sys.stdout.write(text)
        sys.stdout.flush()

    def send(self, text):
        self.proc.stdin.write(text.encode("utf-8"))
        self.proc.stdin.flush()

    def read_until(self, patterns, timeout, start=0):
        if isinstance(patterns, str):
            patterns = [patterns]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            tail = self.buffer[start:]
            for pattern in patterns:
                if pattern in tail:
                    return pattern
            if self.proc.poll() is not None:
                raise TestError(f"QEMU exited before seeing {patterns}")
            events = self.selector.select(0.25)
            for key, _ in events:
                try:
                    data = os.read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                if data:
                    self._record(data)
        raise TestError(f"Timed out waiting for {patterns}")

    def run(self, command, timeout=120):
        self.command_index += 1
        marker = f"__VC_STATUS_{self.command_index:03d}__"
        start = len(self.buffer)
        wrapped = (
            f"printf '\\n__VC_BEGIN_{self.command_index:03d}__\\n'\n"
            "{\n"
            f"{command}\n"
            "}\n"
            f"echo {marker}:$?\n"
        )
        self.send(wrapped)
        deadline = time.monotonic() + timeout
        status_re = re.compile(rf"{re.escape(marker)}:(\d+)")
        while time.monotonic() < deadline:
            tail = self.buffer[start:]
            match = status_re.search(tail)
            if match:
                self.read_until(SHELL_PROMPT, 60, start + match.end())
                tail = self.buffer[start:]
                status = int(match.group(1))
                if status != 0:
                    raise TestError(f"Command failed with status {status}: {command}")
                return tail
            if self.proc.poll() is not None:
                raise TestError(f"QEMU exited while running: {command}")
            events = self.selector.select(0.25)
            for key, _ in events:
                try:
                    data = os.read(key.fileobj.fileno(), 8192)
                except BlockingIOError:
                    continue
                if data:
                    self._record(data)
        raise TestError(f"Timed out running: {command}")


def target_info(target, version):
    if target != "x86/64":
        raise TestError("Only x86/64 is currently supported by this QEMU test")
    return {
        "slug": "x86-64",
        "image": f"openwrt-{version}-x86-64-generic-ext4-combined.img.gz",
        "manifest": f"openwrt-{version}-x86-64.manifest",
        "base_url": f"https://downloads.openwrt.org/releases/{version}/targets/x86/64",
    }


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url, path, expected_sha256=None):
    if path.exists() and expected_sha256:
        actual_sha = sha256_file(path)
        if actual_sha == expected_sha256:
            return
        print(f"Checksum mismatch for existing {path}; re-downloading", file=sys.stderr)
        path.unlink()
    elif path.exists():
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}")
    if tmp.exists():
        tmp.unlink()

    print(f"Downloading {url}")
    try:
        with urllib.request.urlopen(url) as response, open(tmp, "wb") as out:
            shutil.copyfileobj(response, out)
        if expected_sha256:
            actual_sha = sha256_file(tmp)
            if actual_sha != expected_sha256:
                raise TestError(f"SHA-256 mismatch for {path}: expected {expected_sha256}, got {actual_sha}")
        tmp.replace(path)
    finally:
        if tmp.exists():
            tmp.unlink()


def read_text_archive(path):
    data = path.read_bytes()
    if path.name.endswith(".gz"):
        return gzip.decompress(data).decode("utf-8", errors="replace")
    if path.name.endswith(".xz"):
        return lzma.decompress(data).decode("utf-8", errors="replace")
    return data.decode("utf-8", errors="replace")


def expected_sha_from_sums(sums_path, filename):
    with open(sums_path, "r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) >= 2 and parts[1].lstrip("*") == filename:
                return parts[0]
    return None


def sh_quote(text):
    return "'" + str(text).replace("'", "'\"'\"'") + "'"


def read_ar_control_archive(ipk_path):
    with open(ipk_path, "rb") as fh:
        magic = fh.read(8)
        if magic != b"!<arch>\n":
            raise TestError(f"Unsupported .ipk format for {ipk_path}")

        while True:
            header = fh.read(60)
            if not header:
                break
            if len(header) != 60 or header[58:60] != b"`\n":
                raise TestError(f"Malformed ar archive in {ipk_path}")

            name = header[:16].decode("utf-8", errors="replace").strip().rstrip("/")
            size = int(header[48:58].decode("ascii").strip())
            data = fh.read(size)
            if size % 2:
                fh.read(1)

            if Path(name).name.startswith("control.tar"):
                return name, data

    raise TestError(f"No control archive found in {ipk_path}")


def extract_top_level_control_archive(ipk_path):
    with open(ipk_path, "rb") as fh:
        magic = fh.read(8)

    if magic == b"!<arch>\n":
        return read_ar_control_archive(ipk_path)

    try:
        with tarfile.open(ipk_path, "r:*") as outer:
            for member in outer:
                if Path(member.name).name.startswith("control.tar"):
                    member_file = outer.extractfile(member)
                    if member_file:
                        return member.name, member_file.read()
    except tarfile.TarError as exc:
        raise TestError(f"Unsupported .ipk format for {ipk_path}: {exc}") from exc

    raise TestError(f"No control archive found in {ipk_path}")


def open_control_tar(name, data):
    try:
        return tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError:
        pass

    if name.endswith(".zst"):
        zstd = shutil.which("zstd")
        if not zstd:
            raise TestError(f"{name} is zstd-compressed, but zstd was not found")
        result = subprocess.run([zstd, "-dc"], input=data, stdout=subprocess.PIPE, check=False)
        if result.returncode != 0:
            raise TestError(f"zstd failed while reading {name}")
        return tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:")

    if name.endswith(".gz"):
        return tarfile.open(fileobj=io.BytesIO(gzip.decompress(data)), mode="r:")
    if name.endswith(".xz"):
        return tarfile.open(fileobj=io.BytesIO(lzma.decompress(data)), mode="r:")

    raise TestError(f"Unsupported control archive compression: {name}")


def read_control_fields(ipk_path):
    control_name, control_data = extract_top_level_control_archive(ipk_path)
    with open_control_tar(control_name, control_data) as control_tar:
        for member in control_tar:
            if member.name in ("control", "./control") or member.name.endswith("/control"):
                member_file = control_tar.extractfile(member)
                if member_file:
                    text = member_file.read().decode("utf-8", errors="replace")
                    return parse_control_fields(text)
    raise TestError(f"No control file found in {ipk_path}")


def parse_control_fields(text):
    fields = {}
    current = None
    for line in text.splitlines():
        if not line:
            current = None
            continue
        if line[0].isspace() and current:
            fields[current] += "\n" + line.strip()
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        current = key
        fields[key] = value.strip()
    return fields


def parse_control_paragraphs(text):
    paragraphs = []
    lines = []
    for line in text.splitlines():
        if line.strip():
            lines.append(line)
            continue
        if lines:
            paragraphs.append(parse_control_fields("\n".join(lines)))
            lines = []
    if lines:
        paragraphs.append(parse_control_fields("\n".join(lines)))
    return paragraphs


def parse_package_name(text):
    text = re.sub(r"\s*\([^)]*\)", "", text).strip()
    return text.split()[0] if text else ""


def parse_depends(value):
    groups = []
    for item in value.replace("\n", " ").split(","):
        alternatives = [parse_package_name(part) for part in item.split("|")]
        alternatives = [name for name in alternatives if name]
        if alternatives:
            groups.append(alternatives)
    return groups


def parse_name_list(value):
    names = []
    for item in value.replace("\n", " ").split(","):
        name = parse_package_name(item)
        if name:
            names.append(name)
    return names


def infer_package_bin_dir(ipk_path):
    for parent in [ipk_path.parent] + list(ipk_path.parents):
        if parent.name == "bin":
            return parent
    return ipk_path.parent


def read_package_metadata(ipk_path):
    meta = PackageMetadata(ipk_path, read_control_fields(ipk_path))
    if not meta.package:
        raise TestError(f"Package metadata in {ipk_path} has no Package field")
    return meta


def add_package_metadata(index, meta, override=False):
    for name in [meta.package] + meta.provides:
        if name and (override or name not in index):
            index[name] = meta


def build_package_index(package_bin_dir, veracrypt_ipk, skip_local_kmods=False):
    if not package_bin_dir.is_dir():
        raise TestError(f"Package bin directory does not exist: {package_bin_dir}")

    index = {}

    for ipk in sorted(package_bin_dir.rglob("*.ipk")):
        if skip_local_kmods and ipk.name.startswith("kmod-"):
            continue
        add_package_metadata(index, read_package_metadata(ipk))

    add_package_metadata(index, read_package_metadata(veracrypt_ipk), override=True)
    return index


def parse_packages_index(text, feed_url, source):
    index = {}
    feed_url = feed_url.rstrip("/") + "/"
    for fields in parse_control_paragraphs(text):
        package = fields.get("Package", "")
        filename = fields.get("Filename", "")
        if not package or not filename:
            continue
        url = urllib.parse.urljoin(feed_url, filename)
        meta = PackageMetadata(None, fields, url=url, source=source)
        add_package_metadata(index, meta)
    return index


def download_packages_index(index_url, cache_path):
    download(index_url, cache_path)
    return read_text_archive(cache_path)


def official_index_cache_path(work_dir, info, name):
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_")
    return work_dir / "package-indexes" / info["slug"] / safe_name


def kmod_dir_from_kernel_version(version):
    match = re.match(r"^([^~]+)~([0-9a-fA-F]+)-r([0-9A-Za-z_.+-]+)$", version)
    if not match:
        return None
    linux_version, vermagic, release = match.groups()
    return f"{linux_version}-{release}-{vermagic}"


def official_manifest_kernel_version(args, info):
    manifest_url = f"{info['base_url']}/{info['manifest']}"
    cache_path = official_index_cache_path(args.work_dir, info, info["manifest"])
    download(manifest_url, cache_path)
    manifest = read_text_archive(cache_path)
    for line in manifest.splitlines():
        name, sep, version = line.partition(" - ")
        if sep and name == "kernel":
            return version.strip()
    return None


def discover_single_kmod_feed_url(info):
    kmods_url = f"{info['base_url']}/kmods/"
    print(f"Discovering OpenWrt kmod feed from {kmods_url}")
    with urllib.request.urlopen(kmods_url) as response:
        html = response.read().decode("utf-8", errors="replace")
    candidates = sorted(set(re.findall(r'href="([^"/]+-[^"/]+-[0-9a-fA-F]+/)"', html)))
    if len(candidates) == 1:
        return urllib.parse.urljoin(kmods_url, candidates[0]).rstrip("/")
    if not candidates:
        raise TestError(f"Could not discover an OpenWrt kmod feed at {kmods_url}")
    raise TestError(
        "Multiple OpenWrt kmod feeds are available; pass --kmod-feed-url explicitly: "
        + ", ".join(urllib.parse.urljoin(kmods_url, candidate).rstrip("/") for candidate in candidates)
    )


def resolve_official_kmod_feed_url(args, info):
    if args.kmod_feed_url:
        return args.kmod_feed_url.rstrip("/")

    kernel_version = official_manifest_kernel_version(args, info)
    if kernel_version:
        kmod_dir = kmod_dir_from_kernel_version(kernel_version)
        if kmod_dir:
            return f"{info['base_url']}/kmods/{kmod_dir}"

    return discover_single_kmod_feed_url(info)


def official_kmod_package_index(args):
    info = target_info(args.target, args.openwrt_version)
    feed_url = resolve_official_kmod_feed_url(args, info)
    index_url = f"{feed_url}/Packages.gz"
    cache_path = official_index_cache_path(args.work_dir, info, f"kmods-{Path(feed_url).name}-Packages.gz")
    text = download_packages_index(index_url, cache_path)
    index = parse_packages_index(text, feed_url, f"official kmods {feed_url}")
    if not index:
        raise TestError(f"No packages were found in OpenWrt kmod feed {index_url}")
    return index, feed_url


def overlay_package_index(index, overlay):
    seen = set()
    for meta in overlay.values():
        meta_key = meta.identity()
        if meta_key in seen:
            continue
        seen.add(meta_key)
        add_package_metadata(index, meta, override=True)


def resolve_runtime_packages(package_index, seed_packages):
    resolved = []
    resolved_paths = set()
    visiting = set()

    def visit(name, chain):
        if name in PREINSTALLED_PACKAGES:
            return
        meta = package_index.get(name)
        if not meta:
            chain_text = " -> ".join(chain + [name])
            raise TestError(f"Missing .ipk metadata for dependency '{name}' while resolving {chain_text}")

        meta_key = meta.identity()
        if meta_key in resolved_paths:
            return
        if meta_key in visiting:
            return

        visiting.add(meta_key)
        for alternatives in meta.depends:
            selected = None
            for alternative in alternatives:
                if alternative in PREINSTALLED_PACKAGES or alternative in package_index:
                    selected = alternative
                    break
            if not selected:
                chain_text = " -> ".join(chain + [meta.package])
                raise TestError(
                    f"Missing .ipk metadata for dependency '{alternatives[0]}' required by {chain_text}"
                )
            visit(selected, chain + [meta.package])

        visiting.remove(meta_key)
        resolved_paths.add(meta_key)
        resolved.append(meta)

    for package in seed_packages:
        visit(package, [])

    return resolved


def staged_package_name(index, meta):
    return f"{index:03d}-{meta.package_file_name()}"


def ensure_remote_package(meta, cache_dir):
    if not meta.url:
        raise TestError(f"Package {meta.package} has no local path or remote URL")

    file_name = meta.package_file_name()
    cache_name = f"{hashlib.sha256(meta.url.encode('utf-8')).hexdigest()[:12]}-{file_name}"
    cached = cache_dir / cache_name

    def verify_cached():
        if meta.sha256sum and sha256_file(cached) != meta.sha256sum:
            cached.unlink()
            return False
        return True

    if cached.exists() and verify_cached():
        return cached

    download(meta.url, cached, meta.sha256sum)
    if meta.sha256sum and sha256_file(cached) != meta.sha256sum:
        raise TestError(f"SHA-256 mismatch for {cached} downloaded from {meta.url}")
    return cached


def stage_packages(packages, directory, cache_dir):
    directory.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    for index, meta in enumerate(packages):
        source = meta.path if meta.path else ensure_remote_package(meta, cache_dir)
        shutil.copy2(source, directory / staged_package_name(index, meta))


def package_download_command(packages, http_port):
    lines = [
        "set -e",
        "rm -rf /tmp/veracrypt-ipks",
        "mkdir -p /tmp/veracrypt-ipks",
    ]
    for index, meta in enumerate(packages):
        package_name = staged_package_name(index, meta)
        url_path = urllib.parse.quote(package_name, safe="")
        lines.append(
            f"wget -O {sh_quote(f'/tmp/veracrypt-ipks/{package_name}')} "
            f"{sh_quote(f'http://10.0.2.2:{http_port}/{url_path}')}"
        )
    lines.append("opkg install /tmp/veracrypt-ipks/*.ipk")
    return "\n".join(lines)


def prepare_image(args):
    if args.image:
        image = Path(args.image).resolve()
        if not image.exists():
            raise TestError(f"Image does not exist: {image}")
        return image

    info = target_info(args.target, args.openwrt_version)
    image_gz = args.work_dir / "images" / info["image"]
    image = image_gz.with_suffix("")
    sums = args.work_dir / "images" / f"sha256sums-{args.openwrt_version}-{info['slug']}"

    download(f"{info['base_url']}/sha256sums", sums)
    expected_sha = expected_sha_from_sums(sums, info["image"])
    if not expected_sha:
        raise TestError(f"Could not find {info['image']} in {sums}")
    download(f"{info['base_url']}/{info['image']}", image_gz, expected_sha)
    actual_sha = sha256_file(image_gz)
    if actual_sha != expected_sha:
        raise TestError(f"SHA-256 mismatch for {image_gz}: expected {expected_sha}, got {actual_sha}")

    if not image.exists():
        print(f"Extracting {image_gz}")
        with open(image, "wb") as out:
            result = subprocess.run(["gzip", "-cd", str(image_gz)], stdout=out)
        if result.returncode not in (0, 2):
            raise TestError(f"gzip failed while extracting {image_gz}")

    return image


def start_http_server(directory, address, port):
    handler = lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(
        *args, directory=str(directory), **kwargs
    )
    server = ReusableTCPServer((address, port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def boot_qemu(args, image):
    qemu = shutil.which(args.qemu) if os.sep not in args.qemu else args.qemu
    if not qemu:
        raise TestError("qemu-system-x86_64 was not found; install QEMU or pass --qemu")

    netdev = "user,id=net0"
    if args.ssh_port is not None:
        netdev += f",hostfwd=tcp::{args.ssh_port}-:22"

    qemu_cmd = [
        qemu,
        "-accel", args.accel,
        "-M", "pc",
        "-cpu", args.cpu,
        "-m", args.memory,
        "-smp", str(args.smp),
        "-nographic",
        "-drive", f"file={image},format=raw,if=virtio",
        "-netdev", netdev,
        "-device", "virtio-net-pci,netdev=net0",
    ]
    if args.qemu_data_dir:
        qemu_cmd[1:1] = ["-L", str(args.qemu_data_dir)]

    print("Starting QEMU:")
    print(" ".join(qemu_cmd))
    return subprocess.Popen(
        qemu_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def run_guest_tests(args, console, http_port, packages):
    console.read_until(["Please press Enter", SHELL_PROMPT], args.boot_timeout)
    prompt_start = len(console.buffer)
    console.send("\n")
    console.read_until(SHELL_PROMPT, 90, prompt_start)

    console.run(
        "sleep 20\n"
        "if ip link show br-lan >/dev/null 2>&1; then NETDEV=br-lan; else NETDEV=eth0; fi\n"
        "ip addr flush dev \"$NETDEV\" || true\n"
        "ip link set \"$NETDEV\" up\n"
        "udhcpc -n -q -t 10 -i \"$NETDEV\"\n"
        "ip -4 addr show \"$NETDEV\"\n"
        "ping -c 1 10.0.2.2",
        timeout=120,
    )

    console.run(package_download_command(packages, http_port), timeout=900)

    version_output = console.run("veracrypt --text --version", timeout=120)
    if "VeraCrypt " not in version_output:
        raise TestError("version command did not print a VeraCrypt version")

    test_output = console.run("veracrypt --text --test", timeout=240)
    if "Self-tests of all algorithms passed" not in test_output:
        raise TestError("algorithm self-test did not report success")

    if not args.skip_container:
        quoted_container_size = sh_quote(args.container_size)
        quoted_password = sh_quote(args.password)
        console.run("dd if=/dev/urandom of=/tmp/vc-random.bin bs=1M count=1", timeout=120)
        console.run(
            "veracrypt --text --create /tmp/openwrt-test.hc "
            f"--size={quoted_container_size} "
            f"--password={quoted_password} "
            "--encryption=AES --hash=SHA-512 --filesystem=none "
            "--volume-type=normal --random-source=/tmp/vc-random.bin "
            "--quick --force --non-interactive",
            timeout=360,
        )
        console.run("mkdir -p /mnt/veracrypt-test", timeout=60)
        console.run(
            "veracrypt --text --mount /tmp/openwrt-test.hc /mnt/veracrypt-test "
            f"--password={quoted_password} "
            "--pim=0 --keyfiles='' --protect-hidden=no --filesystem=none --non-interactive",
            timeout=240,
        )
        list_output = console.run("veracrypt --text --list", timeout=120)
        if "/dev/mapper/veracrypt" not in list_output:
            raise TestError("container did not appear in veracrypt --list output")
        console.run("veracrypt --text --unmount /tmp/openwrt-test.hc", timeout=180)


def parse_args():
    parser = argparse.ArgumentParser(description="Boot OpenWrt in QEMU and test a VeraCrypt .ipk")
    parser.add_argument("--ipk", required=True, type=Path, help="Path to veracrypt_*.ipk")
    parser.add_argument(
        "--package-bin-dir",
        type=Path,
        help="SDK bin directory containing local dependency .ipk files; defaults to the nearest bin parent of --ipk",
    )
    parser.add_argument("--openwrt-version", default=DEFAULT_OPENWRT_VERSION)
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--work-dir", type=Path, default=None)
    parser.add_argument("--image", type=Path, help="Use an already extracted OpenWrt raw image")
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--qemu-data-dir", type=Path, help="QEMU pc-bios directory for locally extracted QEMU builds")
    parser.add_argument("--accel", default="tcg")
    parser.add_argument("--cpu", default="max")
    parser.add_argument("--memory", default="512M")
    parser.add_argument("--smp", default=1, type=int)
    parser.add_argument(
        "--ssh-port",
        type=int,
        metavar="PORT",
        help="Forward host TCP PORT to guest SSH; disabled by default",
    )
    parser.add_argument("--http-port", default=0, type=int)
    parser.add_argument(
        "--http-bind-address",
        default="127.0.0.1",
        help="Host address for the temporary package server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--kmod-feed-url",
        help="OpenWrt kmod feed URL; defaults to the official feed matching --openwrt-version and --target",
    )
    parser.add_argument(
        "--local-kmods",
        action="store_true",
        help="Resolve kmod-* packages from --package-bin-dir instead of the official OpenWrt kmod feed",
    )
    parser.add_argument("--boot-timeout", default=180, type=int)
    parser.add_argument("--container-size", default="16M")
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument("--skip-container", action="store_true")
    parser.add_argument("--keep-image", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()
    args.ipk = args.ipk.resolve()
    if not args.ipk.exists():
        raise TestError(f"Package does not exist: {args.ipk}")
    if args.package_bin_dir is None:
        args.package_bin_dir = infer_package_bin_dir(args.ipk)
    args.package_bin_dir = args.package_bin_dir.resolve()

    repo_root = Path(__file__).resolve().parents[2]
    if args.work_dir is None:
        args.work_dir = repo_root.parent / "openwrt-veracrypt"
    args.work_dir = args.work_dir.resolve()
    args.work_dir.mkdir(parents=True, exist_ok=True)

    package_index = build_package_index(
        args.package_bin_dir,
        args.ipk,
        skip_local_kmods=not args.local_kmods,
    )
    if not args.local_kmods:
        kmod_index, kmod_feed_url = official_kmod_package_index(args)
        overlay_package_index(package_index, kmod_index)
        print(f"Using OpenWrt kmod feed: {kmod_feed_url}")
    packages = resolve_runtime_packages(package_index, DEFAULT_RUNTIME_PACKAGES)
    print("Resolved OpenWrt packages:")
    for index, meta in enumerate(packages):
        print(f"  {index:02d} {meta.package}: {meta.display_location()}")

    base_image = prepare_image(args)
    test_image = args.work_dir / "images" / f"{base_image.stem}-veracrypt-test.img"
    test_image.parent.mkdir(parents=True, exist_ok=True)
    if test_image.exists():
        test_image.unlink()
    shutil.copyfile(base_image, test_image)

    with tempfile.TemporaryDirectory(prefix="veracrypt-ipks-", dir=args.work_dir) as package_dir:
        server_root = Path(package_dir)
        stage_packages(packages, server_root, args.work_dir / "package-cache")
        server = start_http_server(server_root, args.http_bind_address, args.http_port)
        http_port = server.server_address[1]
        print(f"Serving staged packages from {server_root} on http://{args.http_bind_address}:{http_port}/")

        log_path = args.work_dir / "openwrt-qemu-test.log"
        proc = None
        console = None
        try:
            proc = boot_qemu(args, test_image)
            console = Console(proc, log_path)
            run_guest_tests(args, console, http_port, packages)
            console.send("poweroff\n")
            try:
                proc.wait(timeout=90)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=30)
        finally:
            server.shutdown()
            server.server_close()
            if console:
                console.close()
            if proc and proc.poll() is None:
                proc.terminate()
            if not args.keep_image and test_image.exists():
                test_image.unlink()

    print()
    print("OpenWrt QEMU test passed")
    print(f"Log: {log_path}")


if __name__ == "__main__":
    try:
        main()
    except TestError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
