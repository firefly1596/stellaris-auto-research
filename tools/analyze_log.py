#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auto_research 日志分析工具（适配 2026-11-20 中文格式）

用法：
    python analyze_log.py                    # 默认读游戏目录日志
    python analyze_log.py <日志路径>          # 指定文件
    python analyze_log.py <日志路径> <输出>   # 指定输出 md

输出：
    · 终端摘要
    · <日志名>_report.md（可选）
"""

import sys
import io
import os
import re
import json
from collections import Counter, defaultdict

if sys.platform == 'win32':
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LOG = r'E:\Steam\steamapps\common\Stellaris\injected_mods\auto_research\auto_research.log'

# ============================================================================
# 新格式正则（2026-11-20 中文化后）
# ============================================================================

# [PICK] 领域=物理 候选数=3 候选=[tech_a（中文）,tech_b（中文）] 抽中=1 选中=tech_a（中文） 动作=接管（并列随机）
RE_PICK = re.compile(
    r'\[PICK\]\s+领域=(\S+)\s+候选数=(\d+)\s+候选=\[([^\]]*)\]\s+'
    r'抽中=(-?\d+)\s+选中=(\S+?)(?:\s+动作=(.+))?$'
)

# [TAKE]/[take] n=1 领域=物理 候选数=3 (正数=第1项/权重100 负数=第-1项/0 可读=3 全禁=否) 动作=不干预（随机命中游戏原选）
RE_TAKE = re.compile(
    r'\[(TAKE|take)\]\s+n=(\d+)\s+领域=(\S+)\s+候选数=(\d+)\s+'
    r'\(正数=第(-?\d+)项/权重(-?\d+)\s+负数=第(-?\d+)项/(-?\d+)\s+'
    r'可读=(\d+)\s+全禁=(\S+)\)\s+动作=(.+)$'
)

# [汇总] 总决策=153 真选卡=153 早退=0 玩家=153 AI=0 | 并列=152 撞上原选=36 | [PICK] 接管=116 保留=37
RE_SUMMARY = re.compile(
    r'\[汇总\]\s+总决策=(\d+)\s+真选卡=(\d+)\s+早退=(\d+)\s+玩家=(\d+)\s+AI=(\d+)'
    r'\s*\|\s*并列=(\d+)\s+撞上原选=(\d+)'
    r'(?:\s*\|\s*\[PICK\]\s+接管=(\d+)\s+保留=(\d+))?'
)

# [info] 软件异常 0x40010006（首次出现，非崩溃）
RE_SOFT = re.compile(r'\[info\]\s+软件异常\s+(0x[0-9A-Fa-f]+)')

# !!! CRASH  code=0xC0000005
RE_CRASH = re.compile(r'!!!\s+CRASH\s+code=(0x[0-9A-Fa-f]+)')

# !!! fault module = C:\...
RE_FAULT = re.compile(r'!!!\s+fault module\s*=\s*(.+)$')

# 配置重载 [cfg] reloaded: mode=take default=100 entries=2 | lines=50 ...
RE_CFG = re.compile(r'\[cfg\].*?mode=(\w+).*?default=(-?\d+).*?entries=(\d+)')


def strip_zh(s):
    """把 'tech_xxx（中文名）' 拆成 (key, 中文)"""
    if not s or s == '-':
        return ('', '')
    m = re.match(r'^(.*?)（(.*)）$', s.strip())
    if m:
        return (m.group(1).strip(), m.group(2).strip())
    return (s.strip(), '')


def parse(path):
    recs = {
        'picks': [],
        'takes': [],
        'summary': None,
        'soft': [],
        'crashes': [],
        'faults': [],
        'cfg': [],
        'other': 0,
        'total_lines': 0,
    }

    with open(path, encoding='utf-8', errors='replace') as f:
        for lineno, line in enumerate(f, 1):
            recs['total_lines'] += 1
            L = line.rstrip('\n')

            m = RE_PICK.search(L)
            if m:
                cands = []
                for item in m.group(3).split(','):
                    item = item.strip()
                    if item:
                        k, zh = strip_zh(item)
                        cands.append({'key': k, 'zh': zh})
                sel_key, sel_zh = strip_zh(m.group(5))
                recs['picks'].append({
                    'line': lineno,
                    'area': m.group(1),
                    'cnt': int(m.group(2)),
                    'cand': cands,
                    'ridx': int(m.group(4)),
                    'sel_key': sel_key,
                    'sel_zh': sel_zh,
                    'action': (m.group(6) or '').strip(),
                })
                continue

            m = RE_TAKE.search(L)
            if m:
                recs['takes'].append({
                    'line': lineno,
                    'tag': m.group(1),
                    'n': int(m.group(2)),
                    'area': m.group(3),
                    'cnt': int(m.group(4)),
                    'pos_idx': int(m.group(5)),
                    'pos_w': int(m.group(6)),
                    'neg_idx': int(m.group(7)),
                    'neg_w': int(m.group(8)),
                    'readable': int(m.group(9)),
                    'allzero': m.group(10),
                    'action': m.group(11).strip(),
                })
                continue

            m = RE_SUMMARY.search(L)
            if m:
                recs['summary'] = {
                    'total': int(m.group(1)),
                    'real': int(m.group(2)),
                    'noop': int(m.group(3)),
                    'player': int(m.group(4)),
                    'ai': int(m.group(5)),
                    'tie': int(m.group(6)),
                    'tie_hit': int(m.group(7)),
                    'pick_override': int(m.group(8)) if m.group(8) else None,
                    'pick_keep': int(m.group(9)) if m.group(9) else None,
                }
                continue

            m = RE_SOFT.search(L)
            if m:
                recs['soft'].append({'line': lineno, 'code': m.group(1)})
                continue

            m = RE_CRASH.search(L)
            if m:
                recs['crashes'].append({'line': lineno, 'code': m.group(1)})
                continue

            m = RE_FAULT.search(L)
            if m:
                recs['faults'].append({'line': lineno, 'module': m.group(1).strip()})
                continue

            m = RE_CFG.search(L)
            if m:
                recs['cfg'].append({
                    'line': lineno,
                    'mode': m.group(1),
                    'default': int(m.group(2)),
                    'entries': int(m.group(3)),
                })
                continue

            if L.strip():
                recs['other'] += 1

    return recs


def report(recs, logpath):
    out = []
    w = out.append

    w('# auto_research 日志分析报告\n')
    w('> 源文件：`%s`  ' % logpath)
    w('> 总行数：%d\n' % recs['total_lines'])
    w('---\n')

    # ---------- 一、概览 ----------
    w('## 一、概览\n')
    w('| 项 | 数量 |')
    w('|---|---|')
    w('| 选卡记录（`[PICK]`） | %d |' % len(recs['picks']))
    w('| 决策记录（`[TAKE]`） | %d |' % len(recs['takes']))
    w('| 配置重载（`[cfg]`） | %d |' % len(recs['cfg']))
    w('| 软件异常提示 | %d |' % len(recs['soft']))
    w('| **真崩溃** | **%d** |' % len(recs['crashes']))
    w('')

    # ---------- 二、汇总 ----------
    if recs['summary']:
        s = recs['summary']
        w('## 二、一局汇总\n')
        w('```')
        w('总决策  = %d' % s['total'])
        w('真选卡  = %d' % s['real'])
        w('早退    = %d' % s['noop'])
        w('玩家    = %d' % s['player'])
        w('AI      = %d' % s['ai'])
        w('并列    = %d' % s['tie'])
        if s['tie'] > 0:
            w('撞上原选 = %d  (撞上率 %.1f%%，理论 1/N ≈ 25%%~33%%)'
              % (s['tie_hit'], s['tie_hit'] * 100.0 / s['tie']))
        else:
            w('撞上原选 = %d' % s['tie_hit'])
        if s['pick_override'] is not None:
            w('接管    = %d' % s['pick_override'])
            w('保留    = %d' % s['pick_keep'])
        w('```\n')

        if s['ai'] > 0:
            w('> ⚠️ **AI=%d，说明有非玩家国家被处理了 —— 请报告这个问题**\n' % s['ai'])
    else:
        w('## 二、一局汇总\n')
        w('**没有找到 `[汇总]` 记录。**\n')
        w('> 它只在**正常退出游戏**时打一条。如果是强杀/崩溃退出，看不到是正常的。\n')

    # ---------- 三、动作分布 ----------
    if recs['picks']:
        w('## 三、动作分布（`[PICK]`）\n')
        w('| 动作 | 次数 | 占比 |')
        w('|---|---|---|')
        cnt = Counter(p['action'] for p in recs['picks'])
        n = len(recs['picks'])
        for k, v in cnt.most_common():
            w('| %s | %d | %.1f%% |' % (k or '(空)', v, v * 100.0 / n))
        w('')

        # ---------- 四、按领域 ----------
        w('## 四、按领域分布\n')
        w('| 领域 | 次数 | 其中接管 |')
        w('|---|---|---|')
        by_area = defaultdict(lambda: [0, 0])
        for p in recs['picks']:
            by_area[p['area']][0] += 1
            if p['action'].startswith('接管'):
                by_area[p['area']][1] += 1
        for a in ('物理', '社会', '工程'):
            if a in by_area:
                tot, ov = by_area[a]
                w('| %s | %d | %d (%.1f%%) |' % (a, tot, ov, ov * 100.0 / tot))
        w('')

        # ---------- 五、随机均匀性 ----------
        w('## 五、随机均匀性（抽中位置分布）\n')
        w('> 如果均匀，每个位置出现次数应接近。偏差大说明随机有问题。\n')
        for cnt_val in sorted(set(p['cnt'] for p in recs['picks'] if p['cnt'] > 0)):
            sub = [p for p in recs['picks'] if p['cnt'] == cnt_val and p['ridx'] >= 0]
            if len(sub) < 10:
                continue
            rc = Counter(p['ridx'] for p in sub)
            tot = len(sub)
            exp = tot / float(cnt_val)
            chi2 = sum((rc.get(i, 0) - exp) ** 2 / exp for i in range(cnt_val))
            crit = {2: 3.841, 3: 5.991, 4: 7.815, 5: 9.488}.get(cnt_val)
            verdict = ''
            if crit:
                verdict = '✅ 均匀' if chi2 < crit else '⚠️ 有偏'
            dist = ' / '.join('%d:%d' % (i, rc.get(i, 0)) for i in range(cnt_val))
            w('- **候选数 %d**（%d 次）：%s  → χ²=%.3f%s'
              % (cnt_val, tot, dist, chi2,
                 ('（临界 %.3f）%s' % (crit, verdict)) if crit else ''))
        w('')

        # ---------- 六、候选池频次 ----------
        w('## 六、候选池出现频次（Top 20）\n')
        w('| 科技 | 中文名 | 出现次数 |')
        w('|---|---|---|')
        freq = Counter()
        zh_map = {}
        for p in recs['picks']:
            for c in p['cand']:
                if c['key']:
                    freq[c['key']] += 1
                    if c['zh'] and c['key'] not in zh_map:
                        zh_map[c['key']] = c['zh']
        for k, v in freq.most_common(20):
            w('| `%s` | %s | %d |' % (k, zh_map.get(k, ''), v))
        w('')

        # ---------- 七、选中频次 ----------
        w('## 七、被你（自动科研）选中最多的科技（Top 20）\n')
        w('| 科技 | 中文名 | 选中次数 |')
        w('|---|---|---|')
        sel_freq = Counter()
        sel_zh = {}
        for p in recs['picks']:
            if p['sel_key'] and p['sel_key'] != '-':
                sel_freq[p['sel_key']] += 1
                if p['sel_zh']:
                    sel_zh[p['sel_key']] = p['sel_zh']
        for k, v in sel_freq.most_common(20):
            w('| `%s` | %s | %d |' % (k, sel_zh.get(k, ''), v))
        w('')

    # ---------- 八、配置重载 ----------
    if recs['cfg']:
        w('## 八、配置加载记录\n')
        w('| 行 | 模式 | @default | 条目数 |')
        w('|---|---|---|---|')
        for c in recs['cfg']:
            w('| %d | %s | %d | %d |' % (c['line'], c['mode'], c['default'], c['entries']))
        w('')

        last = recs['cfg'][-1]
        if last['mode'] != 'take':
            w('> ⚠️ **最后一次加载的 mode = `%s`（不是 take）—— 接管不会生效！**\n' % last['mode'])
        if last['entries'] == 0:
            w('> ⚠️ **配置里没有任何科技条目 —— 所有科技都会走 @default。**\n')

    # ---------- 九、崩溃 ----------
    if recs['crashes']:
        w('## 九、崩溃记录\n')
        w('| 行 | 异常码 | 含义 |')
        w('|---|---|---|')
        MEANING = {
            '0xC0000005': '访问违例（访问了非法地址）',
            '0xC000001D': '非法指令',
            '0xC00000FD': '栈溢出',
            '0xC0000409': '栈缓冲区溢出（__fastfail）',
            '0xC0000374': '堆损坏',
        }
        for c in recs['crashes']:
            w('| %d | `%s` | %s |' % (c['line'], c['code'],
                                       MEANING.get(c['code'], '未知硬件异常')))
        w('')
        if recs['faults']:
            w('**崩溃发生在：**\n')
            for f in recs['faults']:
                w('- `%s`' % f['module'])
            w('')
        w('> 把这一段完整发给开发者（包含 `!!! CRASH` 到 `!!! 请把这段发给开发者` 之间的所有行）。\n')
    else:
        w('## 九、崩溃记录\n')
        w('**没有真崩溃（硬件异常）。**\n')

    # ---------- 十、软件异常 ----------
    if recs['soft']:
        w('## 十、游戏正常控制流（非崩溃）\n')
        w('| 行 | 异常码 |')
        w('|---|---|')
        for s in recs['soft']:
            w('| %d | `%s` |' % (s['line'], s['code']))
        w('')
        w('> 这些是游戏自己的调试输出 / C++ 异常 / 线程命名，**不是崩溃**。\n'
          '> 每个异常码只记 1 次，不用管。\n')

    return '\n'.join(out)


def main():
    if len(sys.argv) >= 2:
        logpath = sys.argv[1]
    else:
        logpath = DEFAULT_LOG

    if not os.path.exists(logpath):
        print('[!] 日志不存在：%s' % logpath)
        print('    请确认路径，或先玩一局游戏。')
        sys.exit(1)

    outpath = sys.argv[2] if len(sys.argv) >= 3 else None

    print('读取：%s' % logpath)
    print('  大小 %.1f KB' % (os.path.getsize(logpath) / 1024.0))
    print()

    recs = parse(logpath)

    print('解析结果：')
    print('  [PICK]  选卡记录 : %d' % len(recs['picks']))
    print('  [TAKE]  决策记录 : %d' % len(recs['takes']))
    print('  [cfg]   配置加载 : %d' % len(recs['cfg']))
    print('  软件异常        : %d' % len(recs['soft']))
    print('  真崩溃          : %d' % len(recs['crashes']))
    print()

    if recs['summary']:
        s = recs['summary']
        print('一局汇总：')
        print('  总决策   : %d' % s['total'])
        print('  接管生效 : %s' % (s['pick_override'] if s['pick_override'] is not None else 'N/A'))
        print('  并列     : %d' % s['tie'])
        if s['tie'] > 0:
            print('  撞上率   : %.1f%%' % (s['tie_hit'] * 100.0 / s['tie']))
        print('  AI 误动  : %d%s' % (s['ai'], '  ⚠️' if s['ai'] > 0 else '  ✓'))
    else:
        print('（没有 [汇总] 记录 —— 可能没正常退出游戏）')
    print()

    text = report(recs, logpath)

    if not outpath:
        base = os.path.splitext(os.path.basename(logpath))[0]
        outpath = os.path.join(os.path.dirname(logpath) or '.', base + '_report.md')

    try:
        with open(outpath, 'w', encoding='utf-8') as f:
            f.write(text)
        print('报告：%s (%.1f KB)' % (outpath, os.path.getsize(outpath) / 1024.0))
    except Exception as e:
        print('[!] 写报告失败：%s' % e)
        print('    （日志目录可能不可写，用第二个参数指定输出路径）')


if __name__ == '__main__':
    main()
