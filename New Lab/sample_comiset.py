# -*- coding: utf-8 -*-
import argparse
import json
import random
from collections import defaultdict

def sample_comiset(input_path, output_path, n_normal, n_attack, seed=42):
    random.seed(seed)
    normal_pool = []
    attack_pool = defaultdict(list)

    print("Scanning: " + input_path)
    with open(input_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except:
                continue
            cause = r.get('PossibleCause', 'Unknown')
            ttps = r.get('valid_ttps', ['Unknown Threat'])
            if cause == 'Unknown' or ttps == ['Unknown Threat']:
                normal_pool.append(r)
            else:
                attack_pool[ttps[0]].append(r)

    total_attack = sum(len(v) for v in attack_pool.values())
    print("Normal events : " + str(len(normal_pool)))
    print("Attack events : " + str(total_attack))
    print("Techniques    : " + str(len(attack_pool)))
    for tech, records in sorted(attack_pool.items(), key=lambda x: -len(x[1])):
        print("  " + tech + " -> " + str(len(records)))

    if total_attack == 0:
        print("WARNING: No attack events found!")
        print("Re-convert without --limit:")
        print("  python convert_datasets_to_jsonl.py --source comiset --input .\\Comiset23_Lab_Environment_Dataset")
        return

    sampled_normal = random.sample(normal_pool, min(n_normal, len(normal_pool)))

    per_tech = max(1, n_attack // len(attack_pool))
    sampled_attack = []
    for tech, records in attack_pool.items():
        sampled_attack.extend(random.sample(records, min(per_tech, len(records))))

    remaining = n_attack - len(sampled_attack)
    if remaining > 0:
        used = set(id(r) for r in sampled_attack)
        extra = [r for records in attack_pool.values() for r in records if id(r) not in used]
        sampled_attack.extend(random.sample(extra, min(remaining, len(extra))))

    combined = sampled_normal + sampled_attack
    random.shuffle(combined)

    for i, r in enumerate(combined):
        r['id'] = 'COMISET_SAMPLED_' + str(i).zfill(5)

    with open(output_path, 'w', encoding='utf-8') as f:
        for r in combined:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')

    attack_count = sum(1 for r in combined if r.get('valid_ttps') != ['Unknown Threat'])
    normal_count = len(combined) - attack_count
    print("Done! Normal=" + str(normal_count) + " Attack=" + str(attack_count) + " Total=" + str(len(combined)))
    print("Output: " + output_path)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input',  required=True)
    parser.add_argument('--output', default='mitre_cti_hunting_sampled.jsonl')
    parser.add_argument('--normal', type=int, default=200)
    parser.add_argument('--attack', type=int, default=100)
    parser.add_argument('--seed',   type=int, default=42)
    args = parser.parse_args()
    sample_comiset(args.input, args.output, args.normal, args.attack, args.seed)

if __name__ == '__main__':
    main()