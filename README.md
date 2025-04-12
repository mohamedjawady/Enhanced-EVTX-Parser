# Enhanced EVTX Parser

A comprehensive tool to parse and extract data from Windows XML Event Log (EVTX) files. This parser supports exporting to multiple formats, rendered message retrieval, and deep XML structure conversion to dictionary format.

## Features

- ✅ Supports **JSON**, **CSV**, and **XML** exports
- ✅ Retrieves **rendered event messages** using `pywin32` or **PowerShell fallback**
- ✅ Handles **EventData**, **System**, **UserData**, and **RenderingInfo** sections
- ✅ Cleanly **flattens nested data** for CSV output
- ✅ CLI with detailed options and debugging capabilities

---

## Requirements

- Python 3.7+
- [`python-evtx`](https://github.com/williballenthin/python-evtx)
- [`pywin32`](https://pypi.org/project/pywin32/) *(optional, for rendered messages on Windows)*

Install dependencies:

```bash
pip install python-evtx pywin32
```

---

## Usage

### Command-Line Interface

```bash
python parser.py <path-to-evtx-file> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `-o`, `--output` | Output file path |
| `-f`, `--format` | Output format: `json`, `csv`, or `xml` (default: `json`) |
| `-l`, `--limit` | Limit number of records processed |
| `-c`, `--count` | Print only the total number of records |
| `-d`, `--debug` | Enable debug mode (prints raw XML) |
| `-p`, `--pretty` | Pretty-print JSON output |
| `-r`, `--render-messages` | Enable message rendering (default: True) |
| `--no-render` | Disable message rendering |

### Examples

**Export to JSON (pretty):**
```bash
python parser.py security.evtx -f json -p
```

**Export first 100 records to CSV:**
```bash
python parser.py security.evtx -f csv -l 100
```

**Only show the record count:**
```bash
python parser.py security.evtx -c
```

**Disable message rendering:**
```bash
python parser.py security.evtx --no-render
```

---

## Output Samples

**JSON:** Structured data with full event hierarchy.

**CSV:** Flattened data, ideal for Excel or SIEM ingestion.

**XML:** Raw or enhanced with rendered messages, depending on platform.

---

## Notes

- Windows-only features (rendered messages) require `pywin32`.
- On non-Windows platforms or when `pywin32` is missing, rendering is skipped.
- PowerShell fallback is used for better coverage of event sources.

---

## License

MIT License.

---

## Author

Mohamed Habib Jaouadi

---

Feel free to contribute, report issues, or suggest enhancements!