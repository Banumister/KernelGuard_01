## What does this PR do?

<!-- Link to the relevant docs/ROADMAP.md item or issue -->

## Which week/module does this touch?

- [ ] eBPF (`ebpf/`)
- [ ] Controller (`controller/`)
- [ ] CLI (`cli/`)
- [ ] Policy engine (`policy/`)
- [ ] systemd packaging (`systemd/`)
- [ ] Docs

## Testing

- [ ] `pytest` passes locally
- [ ] `flake8` passes locally
- [ ] If this touches `ebpf/*.c`: tested on a real Linux VM with BCC
      installed (kernel version: ______), not just read for syntax.

## Notes for reviewers

<!-- Anything a reviewer should specifically check, e.g. "does this leak
a kprobe attach if the process is killed mid-run?" -->
