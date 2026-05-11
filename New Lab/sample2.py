import argparse, json, random
from collections import defaultdict

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input',  required=True)
    parser.add_argument('--output', default='sampled.jsonl')
    parser.add_argument('--normal', type=int, default=100)
    parser.add_argument('--attack', type=int, default=200)
    parser.add_argument('--seed',   type=int, default=42)
    args = parser.parse_args()
    random.seed(args.seed)

    normal_pool = []
    attack_pool = defaultdict(list)

    with open(args.input, encoding='utf-8') as f:
        for line in f:
            try:
                r = json.loads(line)
            except:
                continue
            ttps = r.get('valid_ttps', ['Unknown Threat'])
            if ttps == ['Unknown Threat']:
                normal_pool.append(r)
            else:
                attack_pool[ttps[0]].append(r)

    total_attack = sum(len(v) for v in attack_pool.values())
    print('Normal : ' + str(len(normal_pool)))
    print('Attack : ' + str(total_attack))
    print('Techniques: ' + str(len(attack_pool)))
    for k, v in sorted(attack_pool.items(), key=lambda x: -len(x[1]))[:15]:
        print('  ' + k + ' : ' + str(len(v)))

    if total_attack == 0:
        print('ERROR: no attack events found')
        return

    sampled_normal = random.sample(normal_pool, min(args.normal, len(normal_pool)))

    per_tech = max(1, args.attack // len(attack_pool))
    sampled_attack = []
    for k, v in attack_pool.items():
        sampled_attack.extend(random.sample(v, min(per_tech, len(v))))

    combined = sampled_normal + sampled_attack
    random.shuffle(combined)
    for i, r in enumerate(combined):
        r['id'] = 'SAMPLED_' + str(i).zfill(5)

    with open(args.output, 'w', encoding='utf-8') as f:
        for r in combined:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')

    a = sum(1 for r in combined if r.get('valid_ttps') != ['Unknown Threat'])
    print('Output: normal=' + str(len(combined)-a) + ' attack=' + str(a) + ' total=' + str(len(combined)))
    print('File: ' + args.output)

if __name__ == '__main__':
    main()