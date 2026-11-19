import json, os
HERE = os.path.dirname(os.path.abspath(__file__))
main_p = os.path.join(HERE, '..', 'configs', 'servers.json')
cur = json.load(open(main_p, encoding='utf-8-sig')) if os.path.exists(main_p) else []
add = json.load(open(os.path.join(HERE, 'servers.json'), encoding='utf-8'))
have = {s.get('endpoint') for s in cur}
before = len(cur)
for s in add:
    if s['endpoint'] not in have:
        cur.append(s)
        have.add(s['endpoint'])
json.dump(cur, open(main_p, 'w', encoding='utf-8'), indent=2)
print(f'configs/servers.json: {before} -> {len(cur)} (+{len(cur)-before})')
