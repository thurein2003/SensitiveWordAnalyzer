"""Bounded, read-only static analysis of files and directory trees."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .models import FileReport, Finding, ScanReport, Severity
from .rules import RuleSet


ASCII_STRING = re.compile(rb"[\x09\x20-\x7e]{4,}")
UTF16_LE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
UTF16_BE_STRING = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")
URL = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
DOMAIN = re.compile(r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b", re.IGNORECASE)
IPV4_CANDIDATE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
WHITESPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class ScanOptions:
    recursive: bool = True
    include_hidden: bool = False
    follow_symlinks: bool = False
    max_file_size: int = 10 * 1024 * 1024
    max_findings_per_file: int = 200
    max_strings_bytes: int = 2 * 1024 * 1024
    workers: int = 4
    minimum_severity: Severity = Severity.INFO

    def __post_init__(self) -> None:
        if self.max_file_size < 1:
            raise ValueError("max_file_size must be positive")
        if self.max_findings_per_file < 1:
            raise ValueError("max_findings_per_file must be positive")
        if self.max_strings_bytes < 1:
            raise ValueError("max_strings_bytes must be positive")
        if self.workers < 1:
            raise ValueError("workers must be positive")


class Scanner:
    """Scan targets without importing, executing, or modifying their content."""

    def __init__(
        self,
        rules: Optional[RuleSet] = None,
        options: Optional[ScanOptions] = None,
    ) -> None:
        self.rules = rules or RuleSet.default()
        self.options = options or ScanOptions()

    def scan(self, target: Path) -> ScanReport:
        target = target.expanduser().absolute()
        if not target.exists():
            raise FileNotFoundError(f"target does not exist: {target}")

        started_at = datetime.now(timezone.utc).isoformat()
        start = time.monotonic()
        files = sorted(self._discover(target), key=lambda path: str(path).lower())

        if len(files) == 1:
            reports = [self._scan_file(files[0])]
        else:
            with ThreadPoolExecutor(max_workers=self.options.workers) as executor:
                reports = list(executor.map(self._scan_file, files))

        return ScanReport(
            target=str(target),
            started_at=started_at,
            duration_seconds=round(time.monotonic() - start, 6),
            files=reports,
        )

    def _discover(self, target: Path) -> Iterable[Path]:
        if target.is_symlink() and not self.options.follow_symlinks:
            yield target
            return
        if target.is_file():
            yield target
            return

        stack = [target]
        visited: Set[Tuple[int, int]] = set()
        while stack:
            directory = stack.pop()
            try:
                stat = os.stat(directory, follow_symlinks=self.options.follow_symlinks)
                identity = (stat.st_dev, stat.st_ino)
                if identity in visited:
                    continue
                visited.add(identity)
                entries = sorted(directory.iterdir(), key=lambda path: path.name.lower())
            except OSError:
                continue

            child_directories: List[Path] = []
            for entry in entries:
                if entry.name == ".git":
                    continue
                if not self.options.include_hidden and entry.name.startswith("."):
                    continue
                if entry.is_symlink() and not self.options.follow_symlinks:
                    continue
                try:
                    if entry.is_file():
                        yield entry
                    elif entry.is_dir() and self.options.recursive:
                        child_directories.append(entry)
                except OSError:
                    continue
            stack.extend(reversed(child_directories))

    def _scan_file(self, path: Path) -> FileReport:
        try:
            if path.is_symlink() and not self.options.follow_symlinks:
                return FileReport(
                    path=str(path),
                    size=0,
                    file_type="symlink",
                    skipped_reason="symbolic links are disabled",
                )

            size = path.stat().st_size
            if size > self.options.max_file_size:
                return FileReport(
                    path=str(path),
                    size=size,
                    file_type="unknown",
                    skipped_reason=(
                        f"file exceeds the {self.options.max_file_size}-byte size limit"
                    ),
                )

            data = path.read_bytes()
            if len(data) > self.options.max_file_size:
                return FileReport(
                    path=str(path),
                    size=len(data),
                    file_type="unknown",
                    skipped_reason="file grew beyond the configured size limit while reading",
                )

            file_type, segments = self._extract_text(data)
            findings = self._match_rules(segments)
            indicators = self._extract_indicators("\n".join(text for text, _ in segments))
            return FileReport(
                path=str(path),
                size=len(data),
                file_type=file_type,
                hashes=self._hashes(data),
                entropy=self._entropy(data),
                findings=findings,
                indicators=indicators,
            )
        except OSError as exc:
            return FileReport(
                path=str(path),
                size=0,
                file_type="unknown",
                error=f"{type(exc).__name__}: {exc}",
            )

    @staticmethod
    def _hashes(data: bytes) -> Dict[str, str]:
        return {
            "md5": hashlib.md5(data).hexdigest(),  # nosec: useful malware identifier
            "sha1": hashlib.sha1(data).hexdigest(),  # nosec: useful malware identifier
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        length = len(data)
        entropy = -sum(
            (count / length) * math.log2(count / length) for count in Counter(data).values()
        )
        return round(entropy, 4)

    def _extract_text(self, data: bytes) -> Tuple[str, List[Tuple[str, str]]]:
        file_type = self._identify_file_type(data)
        if self._is_probably_text(data):
            return file_type, [(data.decode("utf-8", errors="replace"), "decoded-text")]

        bounded = data[: self.options.max_strings_bytes]
        strings: List[Tuple[str, str]] = []
        for pattern, encoding, source in (
            (ASCII_STRING, "ascii", "ascii-strings"),
            (UTF16_LE_STRING, "utf-16-le", "utf16le-strings"),
            (UTF16_BE_STRING, "utf-16-be", "utf16be-strings"),
        ):
            extracted = "\n".join(
                match.group(0).decode(encoding, errors="replace")
                for match in pattern.finditer(bounded)
            )
            if extracted:
                strings.append((extracted, source))
        return file_type, strings

    @staticmethod
    def _is_probably_text(data: bytes) -> bool:
        if not data:
            return True
        sample = data[:8192]
        if b"\x00" in sample:
            return False
        decoded = sample.decode("utf-8", errors="replace")
        return decoded.count("\ufffd") / max(len(decoded), 1) < 0.01

    @staticmethod
    def _identify_file_type(data: bytes) -> str:
        signatures: Sequence[Tuple[bytes, str]] = (
            (b"MZ", "pe-executable"),
            (b"\x7fELF", "elf-executable"),
            (b"\xcf\xfa\xed\xfe", "mach-o-executable"),
            (b"\xfe\xed\xfa\xcf", "mach-o-executable"),
            (b"PK\x03\x04", "zip-archive"),
            (b"%PDF", "pdf-document"),
            (b"\x89PNG\r\n\x1a\n", "png-image"),
            (b"\x1f\x8b", "gzip-archive"),
        )
        for signature, name in signatures:
            if data.startswith(signature):
                return name
        return "text" if Scanner._is_probably_text(data) else "binary"

    def _match_rules(self, segments: List[Tuple[str, str]]) -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[Tuple[str, str, str, int]] = set()
        for compiled in self.rules.compiled:
            rule = compiled.rule
            if rule.severity.rank < self.options.minimum_severity.rank:
                continue
            for text, source in segments:
                for match in compiled.expression.finditer(text):
                    key = (rule.rule_id, source, match.group(0).casefold(), match.start())
                    if key in seen:
                        continue
                    seen.add(key)
                    line = (
                        text.count("\n", 0, match.start()) + 1
                        if source == "decoded-text"
                        else None
                    )
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            description=rule.description,
                            match=match.group(0)[:160],
                            snippet=self._snippet(text, match.start(), match.end()),
                            source=source,
                            line=line,
                        )
                    )
                    if len(findings) >= self.options.max_findings_per_file:
                        return findings
        return findings

    @staticmethod
    def _snippet(text: str, start: int, end: int, padding: int = 60) -> str:
        excerpt = text[max(0, start - padding) : min(len(text), end + padding)]
        return WHITESPACE.sub(" ", excerpt).strip()[:240]

    @staticmethod
    def _extract_indicators(text: str) -> Dict[str, List[str]]:
        urls = sorted({value.rstrip(".,);]") for value in URL.findall(text)})[:100]
        emails = sorted(set(EMAIL.findall(text)))[:100]
        domains = sorted(set(DOMAIN.findall(text)))[:100]
        ips: List[str] = []
        for candidate in sorted(set(IPV4_CANDIDATE.findall(text))):
            try:
                ips.append(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue

        indicators = {
            "urls": urls,
            "ipv4": ips[:100],
            "emails": emails,
            "domains": domains,
        }
        return {kind: values for kind, values in indicators.items() if values}
