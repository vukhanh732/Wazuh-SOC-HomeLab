"""Summarise exported Wazuh alerts locally. No manager access or file actions."""
import argparse
from collections import Counter
import html
import json
from pathlib import Path
import sys

def cell(value):
    text=html.escape(str(value),quote=True).replace('\\','\\\\')
    for char in ('|','`','[',']','*','_'):text=text.replace(char,'\\'+char)
    return ' '.join(text.split())

def summarize(lines, min_level=0, agent=None):
    levels, agents, techniques, rules = Counter(),Counter(),Counter(),Counter()
    total=0
    for number,line in enumerate(lines,1):
        if not line.strip():continue
        try:
            alert=json.loads(line)
            if not isinstance(alert,dict):raise ValueError('alert must be an object')
            rule=alert.get('rule',{}); endpoint=alert.get('agent',{})
            if not isinstance(rule,dict) or not isinstance(endpoint,dict):raise ValueError('invalid rule/agent')
            level=rule.get('level',0)
            if isinstance(level,bool) or not isinstance(level,int) or not 0<=level<=15:raise ValueError('invalid rule level')
            name=str(endpoint.get('name') or endpoint.get('id') or 'unknown')
            if level<min_level or (agent and agent not in (endpoint.get('name'),endpoint.get('id'))):continue
            mitre=rule.get('mitre') or {}
            if not isinstance(mitre,dict):raise ValueError('invalid MITRE data')
            ids=mitre.get('id',[])
            if not isinstance(ids,list) or any(not isinstance(i,str) for i in ids):raise ValueError('MITRE id must be an array of strings')
            total+=1;levels[level]+=1;agents[name]+=1
            rules[(str(rule.get('id','unknown')),str(rule.get('description','Unlabelled rule')))]+=1
            techniques.update(sorted(set(ids)))
        except (ValueError,TypeError) as exc:
            raise ValueError(f'Line {number}: {exc}') from exc
    parts=['# Wazuh alert triage','',f'**{total} alerts** matched. Minimum rule level: {min_level}. Agent filter: {cell(agent) if agent else "all"}.','',
           'Generated from the supplied export. Counts describe alerts, not unique incidents or confirmed attacks.','']
    def table(title, headings, rows):
        parts.extend(['## '+title,'',' | '.join(headings),' | '.join(['---']*len(headings))])
        parts.extend(' | '.join(cell(v) for v in row) for row in rows)
        if not rows:parts.append(' | '.join(['None']+['0']*(len(headings)-1)))
        parts.append('')
    table('Severity',['Rule level','Alerts'],sorted(levels.items(),reverse=True))
    table('Endpoints',['Agent','Alerts'],agents.most_common())
    table('MITRE ATT&CK',['Technique ID','Alerts'],techniques.most_common())
    table('Detection rules',['Rule','Description','Alerts'],[(r,d,c) for (r,d),c in rules.most_common()])
    return '\n'.join(parts)+'\n'

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('--min-level',type=int,choices=range(16),default=0)
    parser.add_argument('--agent')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args(argv)
    try:
        with args.input.open(encoding='utf-8') as handle:report=summarize(handle,args.min_level,args.agent)
        if args.output:args.output.write_text(report,encoding='utf-8')
        else:sys.stdout.write(report)
    except (OSError,ValueError,UnicodeError) as exc:
        print(str(exc),file=sys.stderr);return 2
    return 0

if __name__=='__main__':raise SystemExit(main())
