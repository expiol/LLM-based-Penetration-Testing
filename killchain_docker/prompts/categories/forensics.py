"""Prompts for forensics challenges."""

from __future__ import annotations

from killchain_docker.prompts.types import CategoryPrompts, register

register(CategoryPrompts(
    category="forensics",
    objective_hint=(
        "Inspect file formats and metadata, extract embedded files, "
        "analyze packet captures for credentials and transferred data, "
        "check disk images for hidden partitions or deleted files, "
        "and examine git repositories for sensitive history."
    ),
    planner_system=(
        "You are planning a forensics CTF challenge. Forensics challenges involve "
        "analyzing digital artifacts: packet captures, disk images, memory dumps, "
        "steganographic images, log files, and git repositories. The flag is "
        "typically hidden within the data and requires careful extraction."
    ),
    planner_focus=(
        "Prioritize: 1) File type identification and metadata extraction, "
        "2) Embedded file extraction (binwalk, foremost, steghide), "
        "3) PCAP analysis for cleartext credentials, HTTP requests, DNS queries, "
        "4) Disk/memory image mounting and deleted file recovery, "
        "5) Git history analysis for leaked secrets in previous commits."
    ),
    analysis_strategy=(
        "For forensics challenges: use file/binwalk to identify file types and "
        "embedded data. For PCAPs: extract HTTP objects, DNS queries, FTP transfers, "
        "and cleartext credentials. For images: check EXIF metadata, LSB steganography, "
        "and appended data after file EOF. For disk images: mount and search for "
        "deleted files, hidden partitions, and alternate data streams."
    ),
    exploit_strategy=(
        "Apply targeted extraction based on artifact type: "
        "binwalk -e for embedded files, tshark/wireshark for PCAP analysis, "
        "steghide/zsteg for image steganography, testdisk/photorec for disk recovery, "
        "volatility for memory forensics. Check git log --all --diff-filter for "
        "secrets in repository history."
    ),
    flag_recovery_hints=[
        "Run binwalk -e to extract embedded files",
        "Check image metadata with exiftool",
        "Try steghide extract with empty password",
        "Filter PCAP for HTTP POST bodies and DNS TXT records",
        "Search git history: git log --all -p | grep -i flag",
        "Mount disk images and search for recently modified files",
    ],
))
