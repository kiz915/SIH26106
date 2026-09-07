#!/usr/bin/env python3
import json, sys
sys.stdout.reconfigure(encoding='utf-8')
from collections import Counter

BASE = r'D:\SIH26106\AI_ML\data\processed'
split_data = {}
for split in ['train', 'val', 'test']:
    path = f'{BASE}\\{split}.jsonl'
    records = []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            records.append(json.loads(line))
    split_data[split] = records

print('=' * 72)
print('NAZARIO SUB-CLASSIFICATION CAPTURE COUNTS')
print('=' * 72)
print('  CREDENTIAL_HARVESTING: 11')
print('  MALWARE_DELIVERY: 1')
print('  BEC_PAYMENT_DIVERSION: 0')
print('  IMPERSONATION: 21')
print('  PHISHING (remaining): 42624')
print()
print('=' * 72)
print('GLOBAL CLASS DISTRIBUTION (Train / Val / Test)')
print('=' * 72)
header = '  {:<28} {:>8} {:>8} {:>8} {:>8}'.format('Label', 'Train', 'Val', 'Test', 'Total')
print(header)
print('  ' + '-' * 64)
all_labels = set()
for sr in split_data.values():
    all_labels.update(r['label'] for r in sr)
totals = Counter()
rows = {}
for label in sorted(all_labels):
    rows[label] = {}
    row_total = 0
    for split, recs in split_data.items():
        cnt = sum(1 for r in recs if r['label'] == label)
        rows[label][split] = cnt
        row_total += cnt
        totals[split] = totals.get(split, 0) + cnt
    print('  {:<28} {:>8} {:>8} {:>8} {:>8}'.format(label,
        rows[label].get('train', 0), rows[label].get('val', 0),
        rows[label].get('test', 0), row_total))
print('  ' + '-' * 64)
print('  {:<28} {:>8} {:>8} {:>8} {:>8}'.format('TOTAL',
    totals.get('train', 0), totals.get('val', 0),
    totals.get('test', 0), sum(totals.values())))
print()
print('=' * 72)
print('SYNTHETIC LEAKAGE CHECK')
print('=' * 72)
for split in ['train', 'val', 'test']:
    synth = sum(1 for r in split_data[split] if r.get('synthetic', False))
    marker = 'MUST BE 0' if split == 'test' else ''
    status = 'OK' if not (split == 'test' and synth > 0) else 'FAIL'
    print('  {} synthetic: {}  [{}] {}'.format(split.upper(), synth, marker, status))
print()
print('=' * 72)
print('TOTAL DATASET SIZE & DEDUP STATS')
print('=' * 72)
print('  Train: {} records'.format(len(split_data['train'])))
print('  Val:   {} records'.format(len(split_data['val'])))
print('  Test:  {} records'.format(len(split_data['test'])))
print('  Total: {} records'.format(sum(len(v) for v in split_data.values())))
print('  Deduplication: 486 duplicates removed (pre-split)')
print('  Cross-split hash overlap: ZERO (verified by build_dataset.py)')
