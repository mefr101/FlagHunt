Drop the files for the current CTF challenge into this directory.

docker-compose mounts it read-only at /workspace inside the container, and the
server's filesystem tools (file_type, strings_extract, binwalk_scan, etc.)
reference files by their name relative to this folder.

Example:
  cp ~/Downloads/challenge.bin ./challenges/
  # then ask the agent: "analyse challenge.bin"
