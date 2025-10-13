# Log Data Flow - From Client to Database

## Complete Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│ CLIENT (pfSense Box)                                                    │
└─────────────────────────────────────────────────────────────────────────┘

Step 1: Read Raw Log Files
───────────────────────────
File: /var/log/filter.log
Content (plain text):
  Oct  1 00:00:00 LNS filterlog[13334]: 5,,,1000000104,vtnet0,match,block...
  Oct  1 00:00:01 LNS filterlog[13334]: 5,,,1000000105,vtnet0,match,pass...
  Oct  1 00:00:02 LNS filterlog[13334]: 5,,,1000000106,vtnet0,match,block...
  
File: /var/log/pfblockerng/ip_block.log
Content (plain text):
  Oct  1 00:00:00,block,vtnet0,103.26.150.122,14.103.21.179,tcp,22
  Oct  1 00:00:01,block,vtnet0,192.168.1.100,8.8.8.8,udp,53

Step 2: Build Raw Logs Array (In Memory)
─────────────────────────────────────────
Python list of dicts:
  raw_logs = [
    {
      'filename': 'filter.log',
      'content': 'Oct  1 00:00:00 LNS filterlog[13334]: 5,...\nOct  1 00:00:01...',
      'size': 123456
    },
    {
      'filename': 'ip_block.log',
      'content': 'Oct  1 00:00:00,block,vtnet0,...\nOct  1 00:00:01...',
      'size': 45678
    }
  ]

Step 3: Convert to JSON String (In Memory)
───────────────────────────────────────────
JSON string:
  '[{"filename":"filter.log","content":"Oct  1 00:00:00 LNS filterlog...","size":123456},...]'
  
Size: ~5 MB (uncompressed)

Step 4: Compress with gzip (In Memory)
───────────────────────────────────────
Binary data (gzip compressed):
  b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\xbd\x07`\x1cI\x96...'
  
Size: ~1 MB (compressed, ~80% reduction)

Step 5: Encode to Base64 String (In Memory)
────────────────────────────────────────────
Base64 string (for JSON transport):
  'H4sIAAAAAAAA/+y9B2AcSZa4+v/pL+hf6Cxr2/Xbdl3/vfdf...'
  
Size: ~1.3 MB (base64 adds ~33% overhead)
Format: ASCII string (safe for JSON)

Step 6: Build Response Dict (In Memory)
────────────────────────────────────────
Python dict:
  {
    'status': 'success',
    'raw_logs': 'H4sIAAAAAAAA/+y9B2AcSZa4+v/pL+hf6Cxr2...',  # ← Base64 string
    'compressed': True,
    'files_count': 15,
    'total_size_bytes': 5234567,
    'date_range': '2025-10-01T00:00:00 to 2025-10-02T00:00:00',
    'files_processed': ['filter.log', 'filter.log.0', ...]
  }

Step 7: Send via WebSocket (Network)
─────────────────────────────────────
WebSocket message (JSON):
  {
    "type": "response",
    "command_id": "f1714731-103d-4614-aeb0-4e0454bb8362",
    "data": {
      "status": "success",
      "raw_logs": "H4sIAAAAAAAA/+y9B2AcSZa4+v/pL+hf6Cxr2...",
      "compressed": true,
      ...
    }
  }

Size on wire: ~1.3 MB
Format: JSON string over WebSocket

┌─────────────────────────────────────────────────────────────────────────┐
│ SERVER (HQ)                                                             │
└─────────────────────────────────────────────────────────────────────────┘

Step 8: Receive WebSocket Message (In Memory)
──────────────────────────────────────────────
Python dict (parsed from JSON):
  message = {
    "type": "response",
    "command_id": "f1714731-103d-4614-aeb0-4e0454bb8362",
    "data": {
      "status": "success",
      "raw_logs": "H4sIAAAAAAAA/+y9B2AcSZa4+v/pL+hf6Czr2...",  # ← Still base64 string
      "compressed": True,
      ...
    }
  }

Step 9: Extract raw_logs Field (In Memory)
───────────────────────────────────────────
Variable assignment:
  logs_data = data.get('raw_logs')
  # logs_data = "H4sIAAAAAAAA/+y9B2AcSZa4+v/pL+hf6Czr2..."
  
Type: str (base64-encoded string)
Size: ~1.3 MB in memory

Step 10: Decode Base64 (In Memory)
───────────────────────────────────
Binary data:
  decoded_data = base64.b64decode(logs_data)
  # decoded_data = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\xbd...'
  
Type: bytes (gzip compressed binary)
Size: ~1 MB in memory

Step 11: Decompress gzip (In Memory)
─────────────────────────────────────
Binary data:
  decompressed_data = gzip.decompress(decoded_data)
  # decompressed_data = b'[{"filename":"filter.log","content":"Oct  1..."}'
  
Type: bytes (uncompressed JSON)
Size: ~5 MB in memory

Step 12: Decode UTF-8 (In Memory)
──────────────────────────────────
String:
  logs_json = decompressed_data.decode('utf-8')
  # logs_json = '[{"filename":"filter.log","content":"Oct  1 00:00:00..."}]'
  
Type: str (JSON string)
Size: ~5 MB in memory

Step 13: Parse JSON (In Memory)
────────────────────────────────
Python list:
  logs_data = json.loads(logs_json)
  # logs_data = [
  #   {'filename': 'filter.log', 'content': 'Oct  1 00:00:00 LNS...', 'size': 123456},
  #   {'filename': 'ip_block.log', 'content': 'Oct  1 00:00:00,block...', 'size': 45678}
  # ]
  
Type: list of dicts
Size: ~5 MB in memory (Python objects)

Step 14: Parse Raw Log Lines (In Memory)
─────────────────────────────────────────
For each file in logs_data:
  filename = 'filter.log'
  content = 'Oct  1 00:00:00 LNS filterlog[13334]: 5,...\nOct  1 00:00:01...'
  
  Split into lines:
    lines = content.split('\n')
    # ['Oct  1 00:00:00 LNS filterlog[13334]: 5,...', 'Oct  1 00:00:01...', ...]
  
  For each line:
    parsed = parse_raw_log_line(line, filename)
    # {
    #   'timestamp': datetime(2025, 10, 1, 0, 0, 0),
    #   'log_timestamp': '2025-10-01T00:00:00',
    #   'source': 'filter.log',
    #   'log_type': 'filter',
    #   'hostname': 'LNS',
    #   'raw_message': 'Oct  1 00:00:00 LNS filterlog[13334]: 5,...',
    #   'rule_number': 5,
    #   'interface': 'vtnet0',
    #   'action': 'block',
    #   'direction': 'out',
    #   'protocol': 'tcp',
    #   'source_ip': '103.26.150.122',
    #   'dest_ip': '14.103.21.179',
    #   'source_port': 22,
    #   'dest_port': 44432
    # }

Result:
  log_entries = [parsed_entry_1, parsed_entry_2, ..., parsed_entry_183049]
  
Type: list of dicts (183,049 entries)
Size: ~50 MB in memory (Python objects with all fields)

Step 15: Insert into Database (Persistent Storage)
───────────────────────────────────────────────────
For each entry in log_entries:
  INSERT INTO log_entries (
    client_id, timestamp, log_timestamp, source, log_type,
    hostname, raw_message, rule_number, interface, action,
    direction, protocol, source_ip, dest_ip, source_port, dest_port
  ) VALUES (
    'opus-1', '2025-10-01 00:00:00', '2025-10-01T00:00:00', 'filter.log', 'filter',
    'LNS', 'Oct  1 00:00:00 LNS filterlog[13334]: 5,...', 5, 'vtnet0', 'block',
    'out', 'tcp', '103.26.150.122', '14.103.21.179', 22, 44432
  )

Storage: SQLite database file (hq_database.db)
Size on disk: ~100 MB (with indexes)
Format: Binary SQLite format

┌─────────────────────────────────────────────────────────────────────────┐
│ FINAL STATE                                                             │
└─────────────────────────────────────────────────────────────────────────┘

Database Table: log_entries
───────────────────────────
183,049 rows, each containing:
  - client_id: 'opus-1'
  - timestamp: 2025-10-01 00:00:00
  - log_timestamp: '2025-10-01T00:00:00'
  - source: 'filter.log'
  - log_type: 'filter'
  - hostname: 'LNS'
  - raw_message: 'Oct  1 00:00:00 LNS filterlog[13334]: 5,...'
  - rule_number: 5
  - interface: 'vtnet0'
  - action: 'block'
  - direction: 'out'
  - protocol: 'tcp'
  - source_ip: '103.26.150.122'
  - dest_ip: '14.103.21.179'
  - source_port: 22
  - dest_port: 44432

Indexes for fast queries:
  - idx_log_entries_client_timestamp (client_id, timestamp)
  - idx_log_entries_action (client_id, action)
  - idx_log_entries_source_ip (client_id, source_ip)
  - idx_log_entries_dest_ip (client_id, dest_ip)
  - idx_log_entries_dest_port (client_id, dest_port)
```

## Key Points

### Data is NEVER stored before decompression/parsing:

1. **Client side**: Data exists only in memory during collection
2. **Network**: Data transmitted as base64-encoded gzip
3. **Server side**: Data decompressed and parsed immediately in memory
4. **Database**: Only the final parsed entries are stored

### Memory Usage:

- **Client**: ~5 MB peak (raw logs in memory)
- **Network**: ~1.3 MB (compressed + base64)
- **Server**: ~50 MB peak (all parsed entries in memory before DB insert)
- **Database**: ~100 MB on disk (with indexes)

### No Intermediate Storage:

❌ **NOT stored** as compressed blob in database  
❌ **NOT stored** as raw logs in database  
❌ **NOT stored** as JSON in database  
✅ **ONLY stored** as individual parsed rows in database

### Why This Design?

1. **Efficient network transfer**: Compressed data is small
2. **No wasted storage**: Don't store raw logs we'll never use again
3. **Fast queries**: Indexed individual rows are much faster than parsing JSON blobs
4. **Memory efficient**: Process and discard, don't accumulate

## Summary

The data flows through these states:

1. **Raw text files** (on pfSense disk)
2. **Python list** (client memory)
3. **JSON string** (client memory)
4. **Gzip binary** (client memory)
5. **Base64 string** (client memory + network)
6. **WebSocket message** (network)
7. **Python dict** (server memory)
8. **Base64 string** (server memory)
9. **Gzip binary** (server memory)
10. **JSON string** (server memory)
11. **Python list** (server memory)
12. **Parsed entries** (server memory)
13. **Database rows** (disk storage)

**At no point is the compressed or raw data stored to disk on the server!** It's decompressed and parsed immediately in memory, then only the parsed entries are stored in the database.

