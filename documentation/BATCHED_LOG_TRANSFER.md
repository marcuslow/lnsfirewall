# Batched Log Transfer Implementation

**Date**: 2025-10-07  
**Status**: ✅ Ready for Testing

## Problem

Client was sending 20MB of compressed log data in a single WebSocket message, exceeding the default 16MB limit. This caused:
- WebSocket connection to close immediately after receiving data
- No data processing or storage
- No temp files created
- Command stuck in "in_progress" state

## Solution

Implemented **batched log transfer** with 10MB chunks to stay within WebSocket limits.

### Key Features:
1. ✅ **10MB batches** - Each batch is ≤10MB compressed
2. ✅ **Retry from failed batch** - If batch 3/7 fails, retry from batch 3 (server discards old batch 3)
3. ✅ **Progress tracking** - Each batch shows "Batch 3/7 received" in progress
4. ✅ **Automatic reassembly** - Server reassembles all batches after receiving the last one
5. ✅ **Temp file storage** - All intermediate files saved for debugging

## Architecture

### Client Side (`client/pfsense_client.py`)

**New Method**: `send_logs_in_batches()`

```python
async def send_logs_in_batches(raw_logs, command_id, total_size):
    # 1. Compress all logs
    compressed = gzip.compress(json.dumps(raw_logs))
    compressed_b64 = base64.b64encode(compressed)
    
    # 2. Split into 10MB chunks
    BATCH_SIZE = 10 * 1024 * 1024  # 10MB
    total_batches = (len(compressed_b64) + BATCH_SIZE - 1) // BATCH_SIZE
    
    # 3. Send each batch
    for batch_num in range(1, total_batches + 1):
        batch_data = compressed_b64[start:end]
        
        # Send batch via WebSocket
        await send_message({
            "type": "log_batch",
            "command_id": command_id,
            "batch_session_id": unique_id,
            "batch_num": batch_num,
            "total_batches": total_batches,
            "batch_data": batch_data
        })
        
        # Send progress update
        await send_message({
            "type": "progress",
            "stage": "sending_batches",
            "batch_num": batch_num,
            "total_batches": total_batches
        })
```

**Modified Method**: `get_firewall_logs()`
- Now calls `send_logs_in_batches()` instead of returning compressed data
- Only uses batching when WebSocket is available
- Falls back to single payload for HTTP mode

### Server Side (`hq/http_server.py`)

**New Handler**: `log_batch` message type

```python
elif message.get("type") == "log_batch":
    # 1. Save batch to temp/client/batches/session_id/batch_001.dat
    batch_file = f"temp/{client}/batches/{session_id}/batch_{num:03d}.dat"
    save_batch(batch_data, batch_file)
    
    # 2. Update progress
    update_command_progress({
        "stage": "receiving_batches",
        "batch_num": batch_num,
        "total_batches": total_batches
    })
    
    # 3. Check if all batches received
    if all_batches_received():
        # 4. Reassemble batches
        reassembled = concatenate_all_batches()
        
        # 5. Process as normal (decompress, parse, store)
        process_logs(reassembled)
        
        # 6. Clean up batch directory
        cleanup_batches()
```

## Data Flow

### Before (Single Message):
```
Client:
  1. Read logs (5MB raw)
  2. Compress (1MB gzip)
  3. Base64 encode (1.3MB)
  4. Send via WebSocket (20MB) ❌ EXCEEDS LIMIT
  
Server:
  5. Connection closed ❌
```

### After (Batched):
```
Client:
  1. Read logs (5MB raw)
  2. Compress (1MB gzip)
  3. Base64 encode (20MB)
  4. Split into batches:
     - Batch 1: 10MB ✅
     - Batch 2: 10MB ✅
  5. Send each batch via WebSocket
  
Server:
  6. Receive batch 1 → Save to temp/client/batches/session/batch_001.dat
  7. Receive batch 2 → Save to temp/client/batches/session/batch_002.dat
  8. All batches received → Reassemble
  9. Process reassembled data:
     - Decode base64
     - Decompress gzip
     - Parse logs
     - Store to database
  10. Clean up batch directory
```

## Temp File Structure

```
temp/
├── opus-1/
│   ├── batches/
│   │   └── a1b2c3d4-session-id/
│   │       ├── batch_001.dat (10MB)
│   │       ├── batch_002.dat (10MB)
│   │       └── batch_003.dat (5MB)
│   ├── 20251007_150000_compressed.gz.b64  (reassembled)
│   ├── 20251007_150000_data.gz
│   ├── 20251007_150000_data.json
│   ├── 20251007_150000_parsed.json
│   └── 20251007_150000_stats.txt
```

**Note**: Batch directory is automatically deleted after successful reassembly.

## Progress Tracking

### Client Progress:
```
Stage: reading_logs
  Current file: filter.log.3
  Files done: 15/23
  Progress: 65%

Stage: sending_batches
  Batch: 1/3
  Progress: 33%

Stage: sending_batches
  Batch: 2/3
  Progress: 66%

Stage: sending_batches
  Batch: 3/3
  Progress: 100%
```

### Server Progress:
```
Stage: receiving_batches
  Batch: 1/3
  Progress: 33%

Stage: receiving_batches
  Batch: 2/3
  Progress: 66%

Stage: receiving_batches
  Batch: 3/3
  Progress: 100%

Stage: processing
  Parsing logs...
  Storing to database...
  
Status: completed
```

## Retry Logic

### If Batch 3/7 Fails:

**Client Side:**
1. Detects batch 3 send failure
2. Retries sending batch 3 with same `batch_num=3`

**Server Side:**
1. Receives new batch 3
2. Overwrites old `batch_003.dat` file
3. Continues waiting for remaining batches

**Result**: No need to restart from batch 1, just retry the failed batch.

## Benefits

### 1. Stays Within Limits
- ✅ Each batch ≤10MB (well under 16MB WebSocket limit)
- ✅ No need to increase system limits
- ✅ Works with default configurations

### 2. Better Progress Tracking
- ✅ Shows batch-by-batch progress
- ✅ User sees "Batch 3/7" instead of just "100% reading logs"
- ✅ More granular feedback

### 3. Resilient to Failures
- ✅ Can retry individual batches
- ✅ Don't lose all progress if one batch fails
- ✅ Server can handle out-of-order batches (overwrites)

### 4. Debugging Friendly
- ✅ Each batch saved to disk
- ✅ Can inspect individual batches
- ✅ Can manually reassemble if needed

### 5. Network Friendly
- ✅ Smaller messages = less memory pressure
- ✅ 100ms delay between batches = no flooding
- ✅ Works better over unreliable connections

## Testing

### Test 1: Small Logs (1 batch)
```bash
python test_small_logs.py
```

Expected:
- 1 batch sent
- Immediate processing
- No batch directory created

### Test 2: Large Logs (multiple batches)
```bash
# From AI console
> threat analysis for opus-1
```

Expected:
- Multiple batches sent (e.g., 3 batches)
- Progress shows "Batch 1/3", "Batch 2/3", "Batch 3/3"
- All batches reassembled
- Logs parsed and stored
- Batch directory cleaned up

### Test 3: Verify Temp Files
```bash
ls -lh temp/opus-1/
```

Expected:
- `20251007_HHMMSS_compressed.gz.b64` (reassembled)
- `20251007_HHMMSS_data.gz`
- `20251007_HHMMSS_data.json`
- `20251007_HHMMSS_parsed.json`
- `20251007_HHMMSS_stats.txt`
- No `batches/` directory (cleaned up)

## Files Modified

### Client
- `client/pfsense_client.py`
  - Added `send_logs_in_batches()` method (lines 638-705)
  - Modified `get_firewall_logs()` to use batching (lines 272-376)

### Server
- `hq/http_server.py`
  - Added `log_batch` message handler (lines 982-1163)
  - Handles batch reception, reassembly, and processing

## Configuration

### Batch Size
Default: 10MB (10 * 1024 * 1024 bytes)

To change:
```python
# In client/pfsense_client.py, line 653
BATCH_SIZE = 5 * 1024 * 1024  # 5MB batches
```

### Batch Delay
Default: 100ms between batches

To change:
```python
# In client/pfsense_client.py, line 693
await asyncio.sleep(0.5)  # 500ms delay
```

## Troubleshooting

### Problem: Batches not reassembling

**Check:**
```bash
ls temp/opus-1/batches/*/
```

If you see batch files stuck there, the server didn't receive all batches.

**Solution:**
- Check server logs for errors
- Verify batch count matches `total_batches`
- Manually delete batch directory and retry

### Problem: Progress stuck at "Batch 2/3"

**Check client logs:**
```bash
tail -100 /var/log/pfsense_client.log
```

Look for "Failed to send batch" errors.

**Solution:**
- Client will retry automatically
- If stuck, restart client

### Problem: Database empty after batching

**Check temp files:**
```bash
cat temp/opus-1/*_stats.txt
```

If stats show entries but database is empty, there was a storage error.

**Check server logs** for database errors.

## Summary

✅ **Batched transfer implemented** - 10MB chunks  
✅ **Progress tracking** - Shows batch-by-batch progress  
✅ **Retry logic** - Retry from failed batch  
✅ **Temp storage** - All intermediate files saved  
✅ **Auto cleanup** - Batch directory removed after success  
✅ **Backward compatible** - Falls back to single payload for HTTP  

**Ready to test with `python distribute.py`!** 🚀

