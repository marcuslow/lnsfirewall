# Temp Files Guide - Debugging Log Processing

## Overview

When the server receives logs from a client, it now saves intermediate files to disk before parsing. This makes debugging **10x easier** because you can inspect exactly what was received and where parsing failed.

## Directory Structure

```
temp/
├── opus-1/
│   ├── 20251002_143000_compressed.gz.b64    # Base64-encoded gzip (as received)
│   ├── 20251002_143000_data.gz              # Decoded gzip binary
│   ├── 20251002_143000_data.json            # Decompressed raw log files
│   ├── 20251002_143000_parsed.json          # Parsed entries (first 100)
│   └── 20251002_143000_stats.txt            # Parsing statistics
├── client-2/
│   └── ...
└── client-3/
    └── ...
```

## File Descriptions

### 1. `{timestamp}_compressed.gz.b64`
**What**: The raw compressed data as received from the client  
**Format**: Base64-encoded gzip  
**Size**: ~1.3 MB  
**Use**: Debug if decompression fails

**Example**:
```
H4sIAAAAAAAA/+y9B2AcSZa4+v/pL+hf6Czr2+Xbdl3/vfdf...
```

### 2. `{timestamp}_data.gz`
**What**: Decoded gzip binary data  
**Format**: Binary gzip  
**Size**: ~1 MB  
**Use**: Debug if gzip decompression fails

**Can decompress manually**:
```bash
gunzip -c temp/opus-1/20251002_143000_data.gz | head
```

### 3. `{timestamp}_data.json`
**What**: Decompressed raw log files  
**Format**: JSON array of log files  
**Size**: ~5 MB  
**Use**: Inspect raw log content before parsing

**Example**:
```json
[
  {
    "filename": "filter.log",
    "content": "Oct  1 00:00:00 LNS filterlog[13334]: 5,,,1000000104,vtnet0,match,block,out,4,0x0,,64,0,0,DF,6,tcp,1128,103.26.150.122,14.103.21.179,22,44432...\nOct  1 00:00:01 LNS filterlog[13334]: ...",
    "size": 123456
  },
  {
    "filename": "ip_block.log",
    "content": "Oct  1 00:00:00,block,vtnet0,103.26.150.122,14.103.21.179,tcp,22\nOct  1 00:00:01,...",
    "size": 45678
  }
]
```

### 4. `{timestamp}_parsed.json`
**What**: Sample of parsed log entries (first 100)  
**Format**: JSON array of parsed entries  
**Size**: ~50 KB  
**Use**: Verify parsing extracted fields correctly

**Example**:
```json
[
  {
    "timestamp": "2025-10-01T00:00:00",
    "log_timestamp": "2025-10-01T00:00:00",
    "source": "filter.log",
    "log_type": "filter",
    "hostname": "LNS",
    "raw_message": "Oct  1 00:00:00 LNS filterlog[13334]: 5,...",
    "rule_number": 5,
    "interface": "vtnet0",
    "action": "block",
    "direction": "out",
    "protocol": "tcp",
    "source_ip": "103.26.150.122",
    "dest_ip": "14.103.21.179",
    "source_port": 22,
    "dest_port": 44432
  },
  ...
]
```

### 5. `{timestamp}_stats.txt`
**What**: Parsing statistics summary  
**Format**: Plain text  
**Size**: ~1 KB  
**Use**: Quick overview of parsing results

**Example**:
```
Parsing Statistics
==================

Total entries: 183,049

By Log Type:
  filter: 172,295
  pfblockerng: 10,732
  unparsed: 22

By Action:
  block: 96,379
  pass: 75,916
  match: 10,732
  None: 22
```

## Debugging Workflow

### Problem: Logs not showing up in database

**Step 1**: Check if files exist
```bash
ls -lh temp/opus-1/
```

**Step 2**: Check stats file
```bash
cat temp/opus-1/20251002_143000_stats.txt
```

If you see high "unparsed" count, proceed to Step 3.

**Step 3**: Inspect raw log content
```bash
cat temp/opus-1/20251002_143000_data.json | jq '.[0].content' | head -20
```

This shows the first 20 lines of the first log file.

**Step 4**: Check parsed sample
```bash
cat temp/opus-1/20251002_143000_parsed.json | jq '.[0]'
```

This shows the first parsed entry with all fields.

**Step 5**: Find unparsed entries
```bash
cat temp/opus-1/20251002_143000_parsed.json | jq '.[] | select(.log_type == "unparsed")'
```

This shows entries that failed to parse.

### Problem: Decompression failed

**Step 1**: Check compressed file exists
```bash
ls -lh temp/opus-1/20251002_143000_compressed.gz.b64
```

**Step 2**: Try manual decompression
```bash
# Decode base64
base64 -d temp/opus-1/20251002_143000_compressed.gz.b64 > /tmp/test.gz

# Decompress gzip
gunzip -c /tmp/test.gz | head
```

If this fails, the client sent corrupted data.

### Problem: Parsing failed for specific log type

**Step 1**: Extract sample lines from raw data
```bash
cat temp/opus-1/20251002_143000_data.json | jq -r '.[0].content' | head -10
```

**Step 2**: Compare with parsed output
```bash
cat temp/opus-1/20251002_143000_parsed.json | jq '.[0]'
```

**Step 3**: Check if fields are extracted
Look for `null` values in parsed output:
```bash
cat temp/opus-1/20251002_143000_parsed.json | jq '.[] | select(.action == null)'
```

## Useful Commands

### Count total log lines in raw data
```bash
cat temp/opus-1/20251002_143000_data.json | jq -r '.[].content' | wc -l
```

### Extract all filter log lines
```bash
cat temp/opus-1/20251002_143000_data.json | jq -r '.[] | select(.filename | contains("filter")) | .content'
```

### Extract all pfBlockerNG log lines
```bash
cat temp/opus-1/20251002_143000_data.json | jq -r '.[] | select(.filename | contains("ip_block")) | .content'
```

### Find specific IP in raw logs
```bash
cat temp/opus-1/20251002_143000_data.json | jq -r '.[].content' | grep "103.26.150.122"
```

### Check parsing success rate
```bash
cat temp/opus-1/20251002_143000_stats.txt | grep -A 10 "By Log Type"
```

## Cleanup

Temp files are automatically ignored by git (see `.gitignore`).

To clean up old temp files:
```bash
# Remove all temp files
rm -rf temp/

# Remove temp files older than 7 days
find temp/ -type f -mtime +7 -delete

# Remove temp files for specific client
rm -rf temp/opus-1/
```

## Benefits

✅ **Easy debugging** - See exactly what was received  
✅ **No guessing** - Inspect raw data before parsing  
✅ **Quick diagnosis** - Stats file shows parsing success rate  
✅ **Manual testing** - Can manually decompress and parse files  
✅ **Historical record** - Keep temp files to track issues over time  

## Summary

Every time logs are received, the server saves:
1. **Compressed data** - As received from client
2. **Gzip binary** - After base64 decode
3. **Raw JSON** - After gzip decompress
4. **Parsed sample** - First 100 parsed entries
5. **Statistics** - Parsing success rates

This makes debugging parsing issues **10x easier** because you can inspect each step of the process!

