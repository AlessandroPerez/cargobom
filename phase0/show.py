import json,sys
d=json.load(open(sys.argv[1]))
for c in d['components']:
    if c['type']!='cryptographic-asset': continue
    p={x['name']:x['value'] for x in c['properties']}
    occ=c['evidence']['occurrences']
    extra=' '.join(f"{k[6:]}={v}" for k,v in p.items() if k not in ('rcbom:detection:method','rcbom:occurrences'))
    print(f"{c['name']:22} {', '.join(sorted({o['location'] for o in occ})):34} n={p['rcbom:occurrences']:>3} {extra}")
