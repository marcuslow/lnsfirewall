#!/usr/bin/env python3

import time
from hq.lqe import LogQueryEngine

print('🚀 Testing LogQueryEngine with sampling (1/10)...')
start_time = time.time()

lqe = LogQueryEngine.from_db('hq_database.db', 'opus-1', since_days=7, sample_rate=10)
end_time = time.time()

print(f'✅ Loaded {len(lqe.entries)} sampled entries in {end_time - start_time:.2f} seconds')
print(f'📊 Performance: {len(lqe.entries) / (end_time - start_time):.0f} entries/second')

# Test analysis speed
print('\n🧪 Testing analysis speed...')
start_time = time.time()
summary = lqe.summarize()
end_time = time.time()

print(f'✅ Analysis completed in {end_time - start_time:.2f} seconds')
print(f'📊 Total entries: {summary["total_entries"]}')
print(f'📊 Blocked: {summary["blocked_count"]}')
print(f'📊 Allowed: {summary["allowed_count"]}')

# Compare with no sampling
print('\n🐌 Testing without sampling (full dataset)...')
start_time = time.time()
lqe_full = LogQueryEngine.from_db('hq_database.db', 'opus-1', since_days=7, sample_rate=1)
end_time = time.time()
print(f'✅ Loaded {len(lqe_full.entries)} full entries in {end_time - start_time:.2f} seconds')

print('\n📊 PERFORMANCE COMPARISON:')
print(f'   Sampled (1/10): {len(lqe.entries):,} entries')
print(f'   Full dataset:   {len(lqe_full.entries):,} entries')
print(f'   Speedup:        {len(lqe_full.entries) / len(lqe.entries):.1f}x faster')
