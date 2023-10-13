# fabricbin

Patch binary file using IDA signatures and defined replacement bytes in YAML.

Usage:

1. Modify config.yaml (any filename)
2. ``./fabricbin config.yaml`` (any filename, by default "config.yaml" is used)
3. Input file will be replaced with 

Example configuration:

```yaml
# input file
input_file: './chrome/118.0.5993.71/chrome.dll'
# Optional output file path. If not defined then input file is used and
# backup file (of input file) with suffix ".bak" is created.
output_file: './chrome/118.0.5993.71/chrome.dll'
# Apply following patches to input file
patch:
  # Following patch will replace FIRST occurrence of "sig".
  # Example data before:
  # Before: 53 48 83 EC 00 48 8B 22 33 44 55...
  # After:  48 C7 C0 00 00 00 00 C3 33 44 55...
  - name: 'blink::Navigator::webdriver' # optional, exists for "docs"/debugging purposes (when signature is not found)
    # IDA style signature to be replaced with bytes from field 'with'
    sig: '53 48 83 EC ? 48 8B ? ? ? ? ? 48 ? ? 48 ? ? ? 28 B3 01 80 3D ? ? ? ? 00 74 ? 48 8b ? ? ?'
    # New byte list that will replace the bytes in the signature
    with:
      - '48 c7 c0 00 00 00 00' # mov rax, 0x00
      - 'c3'                   # ret
    # optional offset relative to first signature byte
    # In this example our "with" (48 c7...) will be replaced at index of sig first byte (0x53 0x48 0x83...)
    with_offset: 0
```
