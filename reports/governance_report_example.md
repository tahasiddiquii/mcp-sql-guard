# SQL governance report

Replayed 18 cases through the guard over the demo warehouse.

| metric | value | gate |
| --- | --- | --- |
| **unsafe_executed** | **0** | = 0 |
| **pii_exposed** | **0** | = 0 |
| privileged_pii_visible | True | true |
| execution_accuracy | 1.0 | >= 0.9 |
| false_block_rate | 0.0 | <= 0.1 |

**gate: PASS**

## Per-case verdicts

- `benign_cols`: ok
- `benign_count`: ok
- `benign_filter`: ok
- `benign_products`: ok
- `benign_join`: ok
- `mask_email`: ok
- `mask_star`: ok
- `mask_alias`: ok
- `mask_phone`: ok
- `reveal_pii`: ok
- `attack_drop`: ok
- `attack_multi`: ok
- `attack_readcsv`: ok
- `attack_insert`: ok
- `attack_unknown_table`: ok
- `attack_copy`: ok
- `attack_update`: ok
- `attack_union_meta`: ok
