#!/usr/bin/env python3
"""
s1_report.py - SentinelOne Analysis Report Generator

Reads a report.json produced by s1_analyzer.py and generates a self-contained
HTML dashboard.  All rendering is done client-side via injected JSON data.

Usage:
    python s1_report.py report.json [-o report.html]
"""

import json
import sys
import argparse
from pathlib import Path


def generate_html(data: dict) -> str:
    """Generate a self-contained HTML dashboard from analysis data."""
    json_blob = json.dumps(data, ensure_ascii=False, default=str)
    template = _get_template()
    return template.replace("/* JSON_INJECT */", json_blob)


def _get_template() -> str:
    return r"""<!DOCTYPE html>
<html lang="fr" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>S1 Analyzer &mdash; SOC Dashboard</title>
<style>
/* ── DESIGN SYSTEM ── */
[data-theme="dark"]{
  --bg-body:#0a0e1a;--bg-primary:#0f1923;--bg-card:#151d2b;--bg-card-hover:#1a2535;
  --bg-input:#1a2332;--border:#1e2d3d;--border-light:#253545;
  --text:#e2e8f0;--text-secondary:#8899aa;--text-muted:#556677;
  --accent:#3b82f6;--accent-glow:rgba(59,130,246,0.15);
  --surface:#151d2b;--surface2:#1a2535;--surface3:#0f1923;
  --primary:#3b82f6;--primary-d:#2563eb;--primary-l:rgba(59,130,246,0.12);
  --red:#ef4444;--red-l:rgba(239,68,68,0.12);--red-d:#f87171;
  --orange:#f97316;--orange-l:rgba(249,115,22,0.12);
  --yellow:#eab308;--yellow-l:rgba(234,179,8,0.12);
  --green:#22c55e;--green-l:rgba(34,197,94,0.12);--green-d:#4ade80;
  --blue:#3b82f6;--blue-l:rgba(59,130,246,0.12);--blue-d:#60a5fa;
  --purple:#a78bfa;--purple-l:rgba(139,92,246,0.15);
  --cyan:#22d3ee;--cyan-l:rgba(6,182,212,0.12);
  --shadow:0 2px 8px rgba(0,0,0,.35),0 1px 3px rgba(0,0,0,.25);
  --shadow-md:0 8px 24px rgba(0,0,0,.4),0 2px 8px rgba(0,0,0,.3);
  --shadow-lg:0 16px 48px rgba(0,0,0,.5),0 4px 16px rgba(0,0,0,.3);
  --dim:#8899aa;--dim2:#556677;
}
[data-theme="light"]{
  --bg-body:#f0f2f7;--bg-primary:#f8f9fc;--bg-card:#ffffff;--bg-card-hover:#f8faff;
  --bg-input:#f0f2f7;--border:#e2e6ef;--border-light:#eef1f8;
  --text:#1a1d2e;--text-secondary:#5a6178;--text-muted:#8a91a8;
  --accent:#4f46e5;--accent-glow:rgba(79,70,229,0.10);
  --surface:#ffffff;--surface2:#f8f9fc;--surface3:#f0f2f7;
  --primary:#4f46e5;--primary-d:#4338ca;--primary-l:rgba(79,70,229,0.08);
  --red:#dc2626;--red-l:#fef2f2;--red-d:#b91c1c;
  --orange:#ea580c;--orange-l:#fff7ed;
  --yellow:#d97706;--yellow-l:#fffbeb;
  --green:#16a34a;--green-l:#f0fdf4;--green-d:#15803d;
  --blue:#2563eb;--blue-l:#eff6ff;--blue-d:#1d4ed8;
  --purple:#7c3aed;--purple-l:#f5f3ff;
  --cyan:#0891b2;--cyan-l:#ecfeff;
  --shadow:0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
  --shadow-md:0 4px 16px rgba(0,0,0,.08),0 2px 6px rgba(0,0,0,.04);
  --shadow-lg:0 10px 40px rgba(0,0,0,.1),0 4px 12px rgba(0,0,0,.05);
  --dim:#64748b;--dim2:#94a3b8;
}
:root{
  --critical:#ef4444;--critical-bg:rgba(239,68,68,0.12);
  --high:#f97316;--high-bg:rgba(249,115,22,0.12);
  --medium:#eab308;--medium-bg:rgba(234,179,8,0.12);
  --low:#22c55e;--low-bg:rgba(34,197,94,0.12);
  --info:#3b82f6;--info-bg:rgba(59,130,246,0.12);
  --radius:12px;--radius-sm:8px;--radius-xs:6px;
  --font-sans:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;
  --font-mono:'Cascadia Code','Fira Code','JetBrains Mono','Courier New',monospace;
  --transition:all .2s cubic-bezier(.4,0,.2,1);
}

*{box-sizing:border-box;margin:0;padding:0;}
html{scroll-behavior:smooth;}
body{background:var(--bg-body);color:var(--text);font-family:var(--font-sans);
  font-size:14px;line-height:1.65;min-height:100vh;transition:background .3s,color .3s;
  padding-top:60px;}
a{color:var(--blue);text-decoration:none;transition:color .15s;}
a:hover{text-decoration:underline;color:var(--blue-d);}
code{font-family:var(--font-mono);font-size:12px;
  background:var(--surface3);border-radius:4px;padding:2px 6px;transition:background .2s;}

.top-bar{position:fixed;top:0;left:0;right:0;z-index:100;
  background:rgba(15,25,35,0.75);backdrop-filter:blur(16px) saturate(180%);
  -webkit-backdrop-filter:blur(16px) saturate(180%);
  border-bottom:1px solid var(--border);transition:background .3s;}
[data-theme="light"] .top-bar{background:rgba(248,249,252,0.8);}
.top-bar-inner{max-width:1440px;margin:0 auto;padding:0 32px;height:56px;
  display:flex;align-items:center;justify-content:space-between;}
.brand{display:flex;align-items:center;gap:12px;}
.brand-icon{width:34px;height:34px;
  background:linear-gradient(135deg,var(--accent),#7c3aed);
  border-radius:9px;display:flex;align-items:center;justify-content:center;
  color:#fff;font-weight:800;font-size:14px;flex-shrink:0;
  box-shadow:0 2px 8px rgba(59,130,246,.3);}
.brand-title{font-size:14px;font-weight:800;color:var(--text);letter-spacing:-.3px;}
.brand-sub{font-size:10px;color:var(--dim);font-weight:500;letter-spacing:.3px;}
.top-actions{display:flex;align-items:center;gap:8px;}
.theme-toggle{display:flex;align-items:center;justify-content:center;
  width:36px;height:36px;border-radius:var(--radius-sm);cursor:pointer;
  font-size:18px;color:var(--dim);background:var(--surface3);
  border:1px solid var(--border);transition:var(--transition);}
.theme-toggle:hover{background:var(--primary-l);color:var(--accent);border-color:var(--accent);}
.theme-icon{line-height:1;}
.btn-print{padding:6px 14px;border-radius:var(--radius-sm);cursor:pointer;
  font-size:12px;font-weight:600;color:var(--dim);background:var(--surface3);
  border:1px solid var(--border);transition:var(--transition);font-family:var(--font-sans);}
.btn-print:hover{background:var(--primary-l);color:var(--accent);border-color:var(--accent);}
.btn-expand{padding:6px 14px;border-radius:var(--radius-sm);cursor:pointer;
  font-size:12px;font-weight:600;color:var(--dim);background:var(--surface3);
  border:1px solid var(--border);transition:var(--transition);font-family:var(--font-sans);}
.btn-expand:hover{background:var(--primary-l);color:var(--accent);border-color:var(--accent);}

.verdict-hero{max-width:1440px;margin:20px auto 0;padding:28px 32px;
  border-radius:var(--radius);display:flex;align-items:center;gap:28px;flex-wrap:wrap;
  transition:var(--transition);border:1px solid var(--border);}
.verdict-hero.critical{background:linear-gradient(135deg,rgba(239,68,68,.12),rgba(239,68,68,.04));border-color:rgba(239,68,68,.25);}
.verdict-hero.high{background:linear-gradient(135deg,rgba(249,115,22,.12),rgba(249,115,22,.04));border-color:rgba(249,115,22,.25);}
.verdict-hero.medium{background:linear-gradient(135deg,rgba(234,179,8,.1),rgba(234,179,8,.03));border-color:rgba(234,179,8,.2);}
.verdict-hero.low{background:linear-gradient(135deg,rgba(34,197,94,.1),rgba(34,197,94,.03));border-color:rgba(34,197,94,.2);}
[data-theme="light"] .verdict-hero.critical{background:linear-gradient(135deg,#fef2f2,#fff1f2);border-color:#fecaca;}
[data-theme="light"] .verdict-hero.high{background:linear-gradient(135deg,#fff7ed,#fffcfa);border-color:#fed7aa;}
[data-theme="light"] .verdict-hero.medium{background:linear-gradient(135deg,#fffbeb,#fffefc);border-color:#fde68a;}
[data-theme="light"] .verdict-hero.low{background:linear-gradient(135deg,#f0fdf4,#fafffe);border-color:#bbf7d0;}
.vh-gauge{text-align:center;min-width:120px;flex-shrink:0;}
.vh-gauge svg{overflow:visible;}
.vh-center{flex:1;min-width:200px;}
.vh-verdict{font-size:22px;font-weight:800;letter-spacing:-.4px;margin-bottom:4px;}
.verdict-hero.critical .vh-verdict{color:var(--critical);}
.verdict-hero.high .vh-verdict{color:var(--high);}
.verdict-hero.medium .vh-verdict{color:var(--medium);}
.verdict-hero.low .vh-verdict{color:var(--low);}
.vh-confidence{font-size:13px;color:var(--dim);font-weight:500;}
.vh-stats{display:flex;gap:20px;flex-wrap:wrap;align-items:center;}
.vh-stat{text-align:center;min-width:70px;}
.vh-stat-num{font-size:24px;font-weight:800;line-height:1.1;}
.vh-stat-lbl{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);font-weight:700;margin-top:2px;}

.bento-grid{max-width:1440px;margin:16px auto 0;padding:0 32px;
  display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:14px;}
.mc{background:var(--bg-card);border-radius:var(--radius);padding:18px 18px 14px;
  box-shadow:var(--shadow);border:1px solid var(--border);
  transition:all .25s cubic-bezier(.4,0,.2,1);position:relative;overflow:hidden;}
.mc::after{content:'';position:absolute;inset:0;border-radius:var(--radius);
  background:linear-gradient(135deg,transparent 60%,var(--accent-glow));pointer-events:none;opacity:0;transition:opacity .3s;}
.mc:hover{box-shadow:var(--shadow-md);transform:translateY(-2px);border-color:var(--border-light);}
.mc:hover::after{opacity:1;}
.mc.alert{border-top:3px solid var(--critical);background:var(--red-l);}
[data-theme="dark"] .mc.alert{background:rgba(239,68,68,0.06);}
.mc.warn{border-top:3px solid var(--high);background:var(--orange-l);}
[data-theme="dark"] .mc.warn{background:rgba(249,115,22,0.06);}
.mc.ok{border-top:3px solid var(--low);}
.mc.info{border-top:3px solid var(--accent);}
.mc .mv{font-size:30px;font-weight:800;line-height:1.1;font-family:var(--font-sans);}
.mc .ml{font-size:11px;color:var(--dim);margin-top:5px;line-height:1.3;}
.mc.alert .mv{color:var(--critical);}
.mc.warn .mv{color:var(--high);}
.mc.ok .mv{color:var(--low);}
.mc.info .mv{color:var(--accent);}

.charts-row{max-width:1440px;margin:16px auto 0;padding:0 32px;
  display:grid;grid-template-columns:1fr 1fr;gap:14px;}
.chart-card{background:var(--bg-card);border-radius:var(--radius);padding:22px;
  box-shadow:var(--shadow);border:1px solid var(--border);transition:var(--transition);}
.chart-card:hover{box-shadow:var(--shadow-md);}
.chart-card.full-width{grid-column:1/-1;}
.chart-title{font-size:11px;text-transform:uppercase;letter-spacing:1px;
  font-weight:700;color:var(--dim);margin-bottom:14px;}
.bar-row{display:flex;align-items:center;gap:10px;margin-bottom:9px;}
.bar-label{font-size:12px;color:var(--text);min-width:90px;font-weight:500;}
.bar-track{flex:1;background:var(--surface3);border-radius:6px;height:10px;overflow:hidden;}
.bar-fill{height:100%;border-radius:6px;transition:width 1.2s cubic-bezier(.4,0,.2,1);}
.bar-count{font-size:12px;color:var(--dim);min-width:28px;text-align:right;font-weight:600;}
.bar-critical{background:linear-gradient(90deg,#dc2626,#ef4444);}
.bar-high{background:linear-gradient(90deg,#ea580c,#f97316);}
.bar-medium{background:linear-gradient(90deg,#d97706,#f59e0b);}
.bar-low{background:linear-gradient(90deg,#16a34a,#22c55e);}
.bar-info{background:linear-gradient(90deg,#64748b,#94a3b8);}
.bar-blue{background:linear-gradient(90deg,var(--accent),#818cf8);}

.wrap{max-width:1440px;margin:0 auto;padding:20px 32px 40px;}
.sections-wrap{display:flex;flex-direction:column;gap:14px;}

.sec{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius);
  overflow:hidden;box-shadow:var(--shadow);transition:all .25s cubic-bezier(.4,0,.2,1);}
.sec:hover{box-shadow:var(--shadow-md);}
.sh{padding:15px 20px;background:var(--bg-card);border-bottom:1px solid transparent;
  cursor:pointer;display:flex;align-items:center;justify-content:space-between;
  user-select:none;transition:var(--transition);}
.sh:hover{background:var(--bg-card-hover);}
.sec:not(.collapsed) .sh{border-bottom-color:var(--border);}
.st{font-weight:700;font-size:12px;text-transform:uppercase;letter-spacing:.6px;
  color:var(--accent);display:flex;align-items:center;gap:8px;}
.sb{font-size:11px;background:var(--surface3);color:var(--dim);padding:4px 12px;
  border-radius:20px;border:1px solid var(--border);white-space:nowrap;font-weight:600;transition:var(--transition);}
.chevron{font-size:11px;color:var(--dim2);transition:transform .3s cubic-bezier(.4,0,.2,1);margin-left:8px;}
.sec.collapsed .chevron{transform:rotate(-90deg);}
.sec.collapsed .sbody{display:none;}
.sbody{padding:20px;animation:fadeIn .3s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}

.badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:var(--radius-xs);
  font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.6px;transition:var(--transition);}
.b-critical{background:var(--critical-bg);color:var(--critical);border:1px solid rgba(239,68,68,.25);}
.b-high{background:var(--high-bg);color:var(--high);border:1px solid rgba(249,115,22,.25);}
.b-medium{background:var(--medium-bg);color:var(--medium);border:1px solid rgba(234,179,8,.25);}
.b-low{background:var(--low-bg);color:var(--low);border:1px solid rgba(34,197,94,.25);}
.b-info{background:var(--surface3);color:var(--dim);border:1px solid var(--border);}
.b-fp{background:var(--low-bg);color:var(--low);border:1px solid rgba(34,197,94,.25);}
.b-signed{color:var(--green);font-weight:700;}
.b-unsigned{color:var(--critical);font-weight:700;}

table{width:100%;border-collapse:collapse;font-size:13px;}
th{text-align:left;padding:10px 14px;background:var(--surface2);color:var(--dim);
  font-size:10px;text-transform:uppercase;letter-spacing:.8px;font-weight:700;border-bottom:2px solid var(--border);}
td{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:top;transition:background .15s;}
tr:last-child td{border-bottom:none;}
tbody tr:hover td{background:var(--surface3);}
tbody tr:nth-child(even) td{background:var(--surface2);}
tbody tr:nth-child(even):hover td{background:var(--surface3);}
.tbl-wrap{overflow-x:auto;border-radius:var(--radius-sm);border:1px solid var(--border);}

.code{background:#0d1117;border:1px solid #21262d;border-radius:var(--radius-xs);
  padding:12px 16px;font-family:var(--font-mono);font-size:12px;
  color:#c9d1d9;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
  line-height:1.7;transition:var(--transition);max-height:400px;overflow-y:auto;}
[data-theme="light"] .code{background:#f6f8fa;border-color:#d0d7de;color:#24292f;}

.ev-list{list-style:none;}
.ev-item{display:flex;gap:10px;padding:10px 14px;margin-bottom:6px;border-radius:var(--radius-sm);font-size:13px;line-height:1.5;transition:var(--transition);}
.ev-item:hover{transform:translateX(3px);}
.ev-tp{background:var(--critical-bg);border-left:3px solid var(--critical);}
.ev-fp{background:var(--low-bg);border-left:3px solid var(--low);}
.ev-obs{background:var(--info-bg);border-left:3px solid var(--info);}
.ev-icon{font-weight:800;flex-shrink:0;margin-top:1px;font-size:13px;}
.ev-tp .ev-icon{color:var(--critical);}
.ev-fp .ev-icon{color:var(--low);}
.ev-obs .ev-icon{color:var(--info);}

.ptree{font-family:var(--font-mono);font-size:13px;line-height:1.9;}
.pnode{padding:3px 0;transition:background .15s;border-radius:4px;padding-left:4px;}
.pnode:hover{background:var(--surface3);}
.pname{font-weight:700;color:var(--text);}
.pcmd{color:var(--dim);font-size:12px;}
.psha{color:var(--dim2);font-size:11px;}
.ppub{color:var(--accent);font-size:12px;}

.ip-unk{color:var(--high);font-weight:700;}
.ip-ok{color:var(--low);}
.unk-badge{font-size:10px;background:var(--high-bg);color:var(--high);
  border:1px solid rgba(249,115,22,.25);padding:2px 8px;border-radius:4px;margin-left:5px;font-weight:600;}

.mitre-grid{display:flex;flex-wrap:wrap;gap:8px;margin-top:4px;}
.mitre-badge{background:var(--purple-l);color:var(--purple);
  border:1px solid rgba(139,92,246,.25);padding:5px 12px;border-radius:var(--radius-xs);
  font-size:12px;font-family:var(--font-mono);font-weight:600;transition:var(--transition);}
.mitre-badge:hover{transform:translateY(-1px);box-shadow:var(--shadow);}
.tactic-badge{background:var(--cyan-l);color:var(--cyan);border:1px solid rgba(6,182,212,.25);
  padding:5px 12px;border-radius:var(--radius-xs);font-size:12px;font-weight:600;transition:var(--transition);}
.tactic-badge:hover{transform:translateY(-1px);box-shadow:var(--shadow);}

.mitre-heatmap{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;}
.mitre-hm-col{background:var(--surface2);border-radius:var(--radius-sm);padding:12px;border:1px solid var(--border);}
.mitre-hm-tactic{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;
  color:var(--cyan);margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--border);}
.mitre-hm-tech{display:inline-block;font-size:11px;padding:3px 8px;border-radius:4px;
  background:var(--purple-l);color:var(--purple);font-family:var(--font-mono);
  font-weight:600;margin:2px 3px 2px 0;border:1px solid rgba(139,92,246,.2);}

.ind-card{border:1px solid var(--border);border-radius:var(--radius-sm);margin-bottom:12px;
  overflow:hidden;transition:all .25s cubic-bezier(.4,0,.2,1);}
.ind-card:hover{box-shadow:var(--shadow-md);transform:translateY(-1px);}
.ind-card.fp{border-color:rgba(34,197,94,.25);background:rgba(34,197,94,.04);}
[data-theme="light"] .ind-card.fp{background:#fafffe;border-color:#bbf7d0;}
.ind-hdr{display:flex;align-items:center;gap:10px;padding:12px 16px;background:var(--surface2);}
.ind-card.fp .ind-hdr{background:var(--low-bg);}
.ind-body{padding:12px 16px;font-size:13px;background:var(--bg-card);}
.ind-row{display:flex;gap:10px;margin-bottom:6px;align-items:flex-start;}
.ind-lbl{color:var(--dim);min-width:90px;font-size:12px;font-weight:600;padding-top:1px;}
.ind-val{flex:1;line-height:1.5;}

[data-tip]{cursor:help;}

.rec-list{list-style:none;}
.rec-item{display:flex;gap:14px;padding:12px 0;border-bottom:1px solid var(--border);transition:var(--transition);}
.rec-item:last-child{border-bottom:none;}
.rec-item:hover{padding-left:6px;}
.rec-num{background:linear-gradient(135deg,var(--accent),#7c3aed);color:#fff;
  width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;
  font-size:11px;font-weight:800;flex-shrink:0;margin-top:1px;box-shadow:0 2px 6px rgba(59,130,246,.25);}
.rec-num.urgent{background:linear-gradient(135deg,var(--critical),#dc2626);box-shadow:0 2px 6px rgba(239,68,68,.3);}

.tl-phases{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px;}
.tl-phase{background:var(--cyan-l);border:1px solid rgba(6,182,212,.25);border-radius:var(--radius-sm);
  padding:10px 16px;font-size:12px;transition:var(--transition);}
.tl-phase:hover{transform:translateY(-2px);box-shadow:var(--shadow);}
.tl-phase-name{font-weight:700;color:var(--cyan);}
.tl-phase-time{color:var(--dim);font-size:11px;margin-top:3px;}

.kv-grid{display:grid;grid-template-columns:160px 1fr;gap:8px 20px;font-size:13px;}
.kv-k{color:var(--dim);font-weight:600;padding-top:2px;}
.kv-v{font-family:var(--font-mono);font-size:12px;word-break:break-all;color:var(--text);}

.alert-box{padding:12px 16px;border-radius:var(--radius-sm);display:flex;gap:10px;align-items:flex-start;transition:var(--transition);}
.alert-box.danger{background:var(--critical-bg);border-left:3px solid var(--critical);}
.alert-box.info{background:var(--info-bg);border-left:3px solid var(--info);}
.alert-box.success{background:var(--low-bg);border-left:3px solid var(--low);}
.alert-box.warn{background:var(--high-bg);border-left:3px solid var(--high);}

.copyable{cursor:pointer;position:relative;transition:var(--transition);border-radius:4px;padding:1px 4px;margin:-1px -4px;}
.copyable:hover{background:var(--primary-l);color:var(--accent);}
.copyable:active{transform:scale(.97);}

#toast-container{position:fixed;bottom:24px;right:24px;z-index:9999;display:flex;flex-direction:column;gap:8px;}
.toast{padding:12px 20px;border-radius:var(--radius-sm);color:#fff;font-size:13px;font-weight:600;
  box-shadow:var(--shadow-lg);animation:slideIn .35s cubic-bezier(.4,0,.2,1) forwards;display:flex;align-items:center;gap:8px;}
.toast.fade-out{opacity:0;transform:translateX(40px);transition:all .4s ease;}
.toast.success{background:#16a34a;}
.toast.info{background:var(--accent);}
@keyframes slideIn{from{opacity:0;transform:translateX(60px)}to{opacity:1;transform:translateX(0)}}

.donut-wrap{display:flex;align-items:center;gap:24px;flex-wrap:wrap;}
.donut-legend{display:flex;flex-direction:column;gap:6px;}
.donut-legend-item{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:500;color:var(--text);}
.donut-legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;}
.donut-legend-count{font-weight:700;margin-left:auto;padding-left:12px;font-family:var(--font-mono);font-size:11px;color:var(--dim);}

.ioc-group{margin-bottom:16px;}
.ioc-group-title{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--cyan);margin-bottom:8px;}
.ioc-item{font-family:var(--font-mono);font-size:12px;padding:4px 10px;margin:3px 0;
  background:var(--surface3);border-radius:4px;display:inline-block;margin-right:6px;cursor:pointer;transition:var(--transition);}
.ioc-item:hover{background:var(--primary-l);color:var(--accent);}

.search-box{width:100%;padding:10px 16px;border-radius:var(--radius-sm);
  background:var(--bg-input);border:1px solid var(--border);color:var(--text);
  font-family:var(--font-sans);font-size:13px;transition:var(--transition);margin-bottom:14px;}
.search-box:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-glow);}
.search-box::placeholder{color:var(--dim2);}

.report-footer{text-align:center;padding:24px 32px;color:var(--dim2);font-size:12px;
  border-top:1px solid var(--border);margin-top:12px;max-width:1440px;margin-left:auto;margin-right:auto;}

@media(max-width:768px){
  .bento-grid{grid-template-columns:repeat(2,1fr);}
  .charts-row{grid-template-columns:1fr;}
  .kv-grid{grid-template-columns:1fr;}
  .verdict-hero{flex-direction:column;text-align:center;}
  .vh-stats{justify-content:center;}
  .top-bar-inner,.bento-grid,.charts-row,.wrap,.verdict-hero{padding-left:16px;padding-right:16px;}
  .mitre-heatmap{grid-template-columns:1fr 1fr;}
}
@media(max-width:480px){
  .bento-grid{grid-template-columns:1fr 1fr;}
  .mitre-heatmap{grid-template-columns:1fr;}
}

@media print{
  .top-bar,.btn-print,.btn-expand,.theme-toggle,#toast-container,.search-box{display:none !important;}
  body{background:#fff;color:#000;font-size:12px;padding-top:0;}
  .sec{break-inside:avoid;box-shadow:none;border:1px solid #ddd;}
  .sec.collapsed .sbody{display:block !important;}
  .mc,.chart-card,.verdict-hero{box-shadow:none;border:1px solid #ddd;}
  .mc:hover,.ind-card:hover,.chart-card:hover{transform:none;}
  .verdict-hero,.bento-grid,.charts-row,.wrap{padding-left:16px;padding-right:16px;max-width:100%;}
  .code{background:#f6f8fa;color:#24292f;border-color:#d0d7de;}
}
.tip-box{position:fixed;z-index:9999;background:rgba(15,25,35,.95);color:#e2e8f0;border:1px solid #1e2d3d;
  border-radius:8px;padding:7px 12px;font-size:12px;max-width:260px;pointer-events:none;
  box-shadow:0 4px 20px rgba(0,0,0,.5);opacity:0;transition:opacity .15s;line-height:1.4;}
[data-theme="light"] .tip-box{background:rgba(255,255,255,.97);color:#1a1d2e;border-color:#e2e6ef;box-shadow:0 4px 16px rgba(0,0,0,.12);}
</style>
</head>
<body>

<div class="top-bar">
  <div class="top-bar-inner">
    <div class="brand">
      <div class="brand-icon">S1</div>
      <div>
        <div class="brand-title">SentinelOne Deep Visibility Analyzer</div>
        <div class="brand-sub" id="brand-sub">SOC Analysis Report</div>
      </div>
    </div>
    <div class="top-actions">
      <button class="btn-expand" onclick="toggleAllSections()" title="Expand/Collapse All">&#9776;</button>
      <button class="btn-print" onclick="window.print()" title="Print / PDF">&#9112; Print</button>
      <div class="theme-toggle" onclick="toggleTheme()" title="Toggle theme (T)">
        <span class="theme-icon">&#9728;</span>
      </div>
    </div>
  </div>
</div>

<div id="verdict-hero"></div>
<div id="bento-grid" class="bento-grid"></div>
<div id="charts-row"></div>
<div id="mitre-heatmap-row"></div>

<div class="wrap">
  <div id="sections" class="sections-wrap"></div>
</div>

<div class="report-footer" id="footer"></div>
<div id="toast-container"></div>

<script>
const DATA = /* JSON_INJECT */;

// ── UTILS ──
function esc(s){var d=document.createElement('div');d.textContent=String(s==null?'':s);return d.innerHTML;}
function copyable(t){return '<span class="copyable" data-copy="'+esc(t)+'">'+esc(t)+'</span>';}

var SEV_MAP={CRITIQUE:'critical',ELEVE:'high',MOYEN:'medium',FAIBLE:'low',INFO:'info'};
var SEV_COLORS={CRITIQUE:'#ef4444',ELEVE:'#f97316',MOYEN:'#eab308',FAIBLE:'#22c55e',INFO:'#3b82f6'};
var SEV_LABELS={CRITIQUE:'Critical',ELEVE:'High',MOYEN:'Medium',FAIBLE:'Low',INFO:'Info/FP'};
function sevClass(s){return SEV_MAP[s]||SEV_MAP[(s||'').toUpperCase()]||'info';}
function sevBadge(s){var c=sevClass(s);var label=SEV_LABELS[s]||SEV_LABELS[(s||'').toUpperCase()]||s;return '<span class="badge b-'+c+'">'+esc(label)+'</span>';}

// ── THEME ──
function toggleTheme(){
  var h=document.documentElement,c=h.getAttribute('data-theme'),n=c==='dark'?'light':'dark';
  h.setAttribute('data-theme',n);localStorage.setItem('s1-theme',n);
  var i=document.querySelector('.theme-icon');if(i)i.textContent=n==='dark'?'\u2600':'\u263E';
}
(function(){
  var s=localStorage.getItem('s1-theme'),p=window.matchMedia('(prefers-color-scheme:light)').matches?'light':'dark';
  var t=s||p;document.documentElement.setAttribute('data-theme',t);
  var i=document.querySelector('.theme-icon');if(i)i.textContent=t==='dark'?'\u2600':'\u263E';
})();
document.addEventListener('keydown',function(e){
  if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA')return;
  if(e.key==='t'||e.key==='T')toggleTheme();
});

// ── TOAST ──
function showToast(msg,type){
  var c=document.getElementById('toast-container');if(!c)return;
  var t=document.createElement('div');t.className='toast '+(type||'info');t.textContent=msg;
  c.appendChild(t);setTimeout(function(){t.classList.add('fade-out');setTimeout(function(){t.remove();},400);},2500);
}
document.addEventListener('click',function(e){
  var el=e.target.closest('.copyable');if(!el)return;
  var text=el.getAttribute('data-copy')||el.textContent.trim();
  if(navigator.clipboard)navigator.clipboard.writeText(text).then(function(){showToast('Copied: '+text.substring(0,40),'success');});
  else{var ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);showToast('Copied: '+text.substring(0,40),'success');}
});

// ── SECTIONS ──
function toggleSection(el){el.parentElement.classList.toggle('collapsed');}
var _allCollapsed=false;
function toggleAllSections(){
  _allCollapsed=!_allCollapsed;
  document.querySelectorAll('.sec').forEach(function(s){
    if(_allCollapsed)s.classList.add('collapsed');else s.classList.remove('collapsed');
  });
}
function makeSection(id,title,badge,bodyHtml,collapsed){
  return '<div class="sec'+(collapsed?' collapsed':'')+'" id="sec-'+id+'">'+
    '<div class="sh" onclick="toggleSection(this)">'+
      '<span class="st">'+title+'</span>'+
      '<span>'+(badge?'<span class="sb">'+esc(badge)+'</span>':'')+'<span class="chevron">&#9660;</span></span>'+
    '</div>'+
    '<div class="sbody">'+bodyHtml+'</div>'+
  '</div>';
}

// ── ANIMATIONS ──
function animateCounters(){
  document.querySelectorAll('[data-count]').forEach(function(el){
    var target=parseInt(el.dataset.count,10)||0;
    if(target===0){el.textContent='0';return;}
    var dur=1200,start=performance.now();
    function up(now){var e=now-start,p=Math.min(e/dur,1),ea=1-Math.pow(1-p,3);
      el.textContent=Math.round(target*ea);if(p<1)requestAnimationFrame(up);}
    requestAnimationFrame(up);
  });
}
function animateBars(){
  document.querySelectorAll('.bar-fill[data-w]').forEach(function(b){
    b.style.width='0';requestAnimationFrame(function(){requestAnimationFrame(function(){b.style.width=b.dataset.w+'%';});});
  });
}
function drawGauge(){
  var g=document.getElementById('gauge-arc');if(!g)return;
  var score=parseFloat(g.dataset.score)||0,max=parseFloat(g.dataset.max)||20;
  var pct=Math.min(Math.max(score/max,0),1);
  var R=42,cx=50,cy=52,sa=-220,sw=260;
  var rad=function(a){return a*Math.PI/180;};
  var arc=function(a){return[cx+R*Math.cos(rad(a)),cy+R*Math.sin(rad(a))];};
  var s=arc(sa),e=arc(sa+sw*pct),large=sw*pct>180?1:0;
  if(pct===0){g.setAttribute('d','');return;}
  g.setAttribute('d','M'+s[0]+','+s[1]+' A'+R+','+R+' 0 '+large+',1 '+e[0]+','+e[1]);
  var len=g.getTotalLength?g.getTotalLength():200;
  g.style.strokeDasharray=len;g.style.strokeDashoffset=len;
  requestAnimationFrame(function(){requestAnimationFrame(function(){
    g.style.transition='stroke-dashoffset 1.5s cubic-bezier(.4,0,.2,1)';g.style.strokeDashoffset=0;
  });});
}

// ═══════════════════════════════════════════════════════════════
// VERDICT HERO — matches generate_html() exactly
// ═══════════════════════════════════════════════════════════════
function renderVerdictHero(){
  var v=DATA.verdict||{},id=DATA.identification||{},m=DATA.metrics||{},tl=DATA.timeline||{};
  var score=v.score||0,maxS=20;
  var vt=v.verdict||'';
  // Verdict classification matching generate_html
  var verdictClass,verdictIcon;
  if(vt.indexOf('TRUE POSITIVE')>=0){verdictClass='critical';verdictIcon='&#9888;';}
  else if(vt.indexOf('SUSPICIOUS')>=0){verdictClass='high';verdictIcon='&#9888;';}
  else if(vt.indexOf('UNDETERMINED')>=0){verdictClass='medium';verdictIcon='&#9679;';}
  else if(vt.indexOf('LIKELY FALSE')>=0||vt.indexOf('LIKELY BENIGN')>=0){verdictClass='low';verdictIcon='&#10003;';}
  else{verdictClass='low';verdictIcon='&#10003;';}
  var scoreClass=score>=16?'critical':score>=12?'high':score>=8?'medium':score>=4?'low':'low';
  var gc={critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e'}[scoreClass]||'#3b82f6';

  // Process name with cmdline fallback
  var proc=id.process||'Unknown';
  var user=(id.user||'N/A').split('osSrc')[0].trim()||'N/A';
  var tsRange=tl.start&&tl.end?esc(tl.start)+' \u2192 '+esc(tl.end):'N/A';

  var tp=v.evidence_tp||[],fp=v.evidence_fp||[],obs=v.observations||[];

  var h='<section class="verdict-hero '+verdictClass+'">';
  // Gauge SVG
  h+='<div class="vh-gauge"><svg viewBox="0 0 100 80" width="130" height="104">';
  h+='<path d="M10.4,69.6 A42,42 0 1,1 89.6,69.6" fill="none" stroke="var(--border)" stroke-width="8" stroke-linecap="round" opacity="0.5"/>';
  h+='<path id="gauge-arc" data-score="'+score+'" data-max="'+maxS+'" fill="none" stroke="'+gc+'" stroke-width="8" stroke-linecap="round"/>';
  h+='<text x="50" y="55" text-anchor="middle" font-family="Inter,Segoe UI,system-ui,sans-serif" font-size="24" font-weight="800" fill="'+gc+'">'+score+'</text>';
  h+='<text x="50" y="70" text-anchor="middle" font-family="Inter,Segoe UI,system-ui,sans-serif" font-size="8" fill="var(--dim)" letter-spacing="1.5">SCORE / '+maxS+'</text>';
  h+='</svg></div>';
  // Center
  h+='<div class="vh-center">';
  h+='<div class="vh-verdict">'+verdictIcon+' '+esc(vt)+'</div>';
  h+='<div class="vh-confidence">Confidence: <strong style="color:var(--text)">'+esc(v.confidence||'N/A')+'</strong>';
  h+=' &nbsp;&#183;&nbsp; Process: <strong style="color:var(--text)" class="copyable" data-copy="'+esc(proc)+'">'+esc(proc)+'</strong>';
  h+=' &nbsp;&#183;&nbsp; User: <strong style="color:var(--text)">'+esc(user)+'</strong>';
  h+=' &nbsp;&#183;&nbsp; Period: <strong style="color:var(--text)">'+tsRange+'</strong></div>';
  h+='</div>';
  // Stats — TP Evidence / Mitigating / Observations
  h+='<div class="vh-stats">';
  h+='<div class="vh-stat"><div class="vh-stat-num" style="color:var(--critical)" data-count="'+tp.length+'">0</div><div class="vh-stat-lbl">TP Evidence</div></div>';
  h+='<div class="vh-stat"><div class="vh-stat-num" style="color:var(--low)" data-count="'+fp.length+'">0</div><div class="vh-stat-lbl">Mitigating</div></div>';
  h+='<div class="vh-stat"><div class="vh-stat-num" style="color:var(--info)" data-count="'+obs.length+'">0</div><div class="vh-stat-lbl">Observations</div></div>';
  h+='</div></section>';
  document.getElementById('verdict-hero').innerHTML=h;
}

// ═══════════════════════════════════════════════════════════════
// BENTO METRICS — 10 cards matching generate_html
// ═══════════════════════════════════════════════════════════════
function renderBentoGrid(){
  var m=DATA.metrics||{};
  var cards=[
    {v:m.indicators||0, l:'Indicators<br>'+(m.critical||0)+' critical', cls:(m.critical>0?'alert':'ok'), tip:'Behavioral indicators triggered', sec:'indicators'},
    {v:m.ext_connections||0, l:'Ext. Connections<br>'+(m.unknown_connections||0)+' unknown', cls:(m.unknown_connections>0?'warn':'ok'), tip:'External network connections', sec:'network'},
    {v:m.script_findings||0, l:'Script Findings', cls:(m.script_findings>0?'alert':'ok'), tip:'Malicious script patterns', sec:'scripts'},
    {v:m.persistence_keys||0, l:'Persistence Keys', cls:(m.persistence_keys>0?'alert':'ok'), tip:'Persistence registry keys', sec:'registry'},
    {v:m.suspicious_files||0, l:'Suspicious Files', cls:(m.suspicious_files>0?'alert':'ok'), tip:'Suspicious file operations', sec:'files'},
    {v:m.sigma_matches||0, l:'Sigma Matches', cls:(m.sigma_matches>0?'alert':'ok'), tip:'Sigma community rule matches', sec:'sigma'},
    {v:m.yara_matches||0, l:'YARA Matches', cls:(m.yara_matches>0?'alert':'ok'), tip:'YARA pattern matches', sec:'yara'},
    {v:m.graph_anomalies||0, l:'Graph Anomalies', cls:(m.graph_anomalies>0?'alert':'ok'), tip:'Process graph anomalies (NetworkX)', sec:'pgraph'},
    {v:m.stat_outliers||0, l:'Stat. Outliers', cls:(m.stat_outliers>0?'warn':'ok'), tip:'Statistical outliers (IsolationForest)', sec:'stats'},
    {v:m.total_events||0, l:'Total Events', cls:'info', tip:'Total Deep Visibility events analyzed', sec:'timeline'}
  ];
  var h='';
  cards.forEach(function(c){
    h+='<div class="mc '+c.cls+'" data-tip="'+c.tip+'" style="cursor:pointer" onclick="scrollToSec(\''+c.sec+'\')"><div class="mv" data-count="'+c.v+'">'+c.v+'</div><div class="ml">'+c.l+'</div></div>';
  });
  document.getElementById('bento-grid').innerHTML=h;
}
function scrollToSec(id){
  var el=document.getElementById('sec-'+id);
  if(!el)return;
  if(el.classList.contains('collapsed'))toggleSection(el.querySelector('.sh'));
  el.scrollIntoView({behavior:'smooth',block:'start'});
  el.style.boxShadow='0 0 0 2px var(--accent)';
  setTimeout(function(){el.style.boxShadow='';},1500);
}

// ═══════════════════════════════════════════════════════════════
// CHARTS ROW — SVG Donut + Event Type Bar Chart
// ═══════════════════════════════════════════════════════════════
function renderChartsRow(){
  var sev=DATA.severity_distribution||{};
  var evt=(DATA.timeline||{}).event_type_distribution||{};
  var h='<div class="charts-row">';

  // ── Donut: Indicator Severity Distribution (SVG arcs like generate_html) ──
  h+='<div class="chart-card"><div class="chart-title">Indicator Severity Distribution</div>';
  var sevOrder=['CRITIQUE','ELEVE','MOYEN','FAIBLE','INFO'];
  var sevTotal=0;sevOrder.forEach(function(k){sevTotal+=(sev[k]||0);});
  if(sevTotal>0){
    var R=70,inner=45,sw=R-inner,cr=(R+inner)/2,circ=2*Math.PI*cr,offset=0;
    h+='<div class="donut-wrap"><svg viewBox="0 0 180 180" width="170" height="170">';
    sevOrder.forEach(function(k){
      var v=sev[k]||0;if(v===0)return;
      var pct=v/sevTotal,dash=circ*pct,gap=circ-dash;
      h+='<circle cx="90" cy="90" r="'+cr.toFixed(1)+'" fill="none" stroke="'+SEV_COLORS[k]+'" stroke-width="'+sw+'" stroke-dasharray="'+dash.toFixed(2)+' '+gap.toFixed(2)+'" stroke-dashoffset="'+(-offset).toFixed(2)+'" transform="rotate(-90 90 90)"/>';
      offset+=dash;
    });
    h+='<text x="90" y="85" text-anchor="middle" fill="var(--text)" font-family="Inter,Segoe UI,system-ui,sans-serif" font-size="28" font-weight="800">'+sevTotal+'</text>';
    h+='<text x="90" y="105" text-anchor="middle" fill="var(--dim)" font-family="Inter,Segoe UI,system-ui,sans-serif" font-size="10" letter-spacing="1">INDICATORS</text>';
    h+='</svg><div class="donut-legend">';
    sevOrder.forEach(function(k){
      h+='<div class="donut-legend-item"><span class="donut-legend-dot" style="background:'+SEV_COLORS[k]+'"></span>'+SEV_LABELS[k]+'<span class="donut-legend-count">'+(sev[k]||0)+'</span></div>';
    });
    h+='</div></div>';
  } else {
    h+='<p style="color:var(--dim)">No indicators</p>';
  }
  h+='</div>';

  // ── Bar chart: Event Type Distribution (top 10) ──
  h+='<div class="chart-card"><div class="chart-title">Event Type Distribution</div>';
  var evtEntries=Object.entries(evt).sort(function(a,b){return b[1]-a[1];}).slice(0,10);
  var evtMax=evtEntries.length>0?evtEntries[0][1]:1;
  if(evtEntries.length>0){
    evtEntries.forEach(function(e){
      var pct=Math.round(e[1]/evtMax*100);
      h+='<div class="bar-row"><span class="bar-label">'+esc(e[0])+'</span>';
      h+='<div class="bar-track"><div class="bar-fill bar-blue" data-w="'+pct+'"></div></div>';
      h+='<span class="bar-count">'+e[1]+'</span></div>';
    });
  } else {
    h+='<p style="color:var(--dim)">No event data</p>';
  }
  h+='</div></div>';
  document.getElementById('charts-row').innerHTML=h;
}

// ═══════════════════════════════════════════════════════════════
// MITRE HEATMAP — separate full-width chart card
// ═══════════════════════════════════════════════════════════════
function renderMitreHeatmap(){
  var ma=DATA.mitre_attack||{};
  var heatmap=ma.heatmap||{};
  var techniques=ma.techniques||[];
  var me=DATA.mitre_enrichment||{};
  var meTechs=me.techniques||[];

  // Build tactic->technique map from heatmap data
  var tacMap={};
  var hmKeys=Object.keys(heatmap);
  if(hmKeys.length>0){
    tacMap=heatmap;
  }
  // Enrich with mitre_enrichment data if heatmap is sparse
  if(meTechs.length>0&&hmKeys.length===0){
    meTechs.forEach(function(t){
      var tac=t.tactic||'Other';
      if(!tacMap[tac])tacMap[tac]=[];
      if(!tacMap[tac].some(function(x){return x.id===t.id;}))
        tacMap[tac].push({id:t.id,name:t.name});
    });
  }

  var keys=Object.keys(tacMap);
  if(keys.length===0){document.getElementById('mitre-heatmap-row').innerHTML='';return;}

  var h='<div class="charts-row" style="margin-top:16px"><div class="chart-card full-width">';
  h+='<div class="chart-title">MITRE ATT&amp;CK Coverage Heatmap</div>';
  h+='<div class="mitre-heatmap">';
  keys.sort().forEach(function(tac){
    h+='<div class="mitre-hm-col"><div class="mitre-hm-tactic">'+esc(tac)+'</div>';
    (tacMap[tac]||[]).forEach(function(t){
      var tid=typeof t==='string'?t:(t.id||'?');
      var tname=typeof t==='object'?(t.name||''):'';
      var tip=tname?' title="'+esc(tname)+'"':'';
      h+='<span class="mitre-hm-tech"'+tip+'>'+esc(tid)+'</span>';
    });
    h+='</div>';
  });
  h+='</div></div></div>';
  document.getElementById('mitre-heatmap-row').innerHTML=h;
}

// ═══════════════════════════════════════════════════════════════
// SECTION RENDERERS
// ═══════════════════════════════════════════════════════════════

function renderIdentification(){
  var id=DATA.identification||{};
  var meta=DATA.meta||{};
  var isSDL=(meta.csv_format==='SDL');
  var signed=id.signed||'';
  var signHtml;
  if(signed==='signed')signHtml='<span class="b-signed">&#10003; Signed</span>';
  else if(!signed)signHtml='<span style="color:var(--dim);font-size:12px">Not available'+(isSDL?' (SDL format)':'')+'</span>';
  else signHtml='<span class="b-unsigned">&#10007; '+esc(signed)+'</span>';
  var sha1Val=id.sha1||'';
  var sha1Html=sha1Val?copyable(sha1Val):'<span style="color:var(--dim);font-size:12px">Not available'+(isSDL?' (SDL format)':'')+'</span>';
  var pubVal=id.publisher||'';
  var pubHtml=pubVal?esc(pubVal):'<span style="color:var(--dim);font-size:12px">Not available'+(isSDL?' (SDL format)':'')+'</span>';
  var h='<div class="kv-grid">';
  h+='<div class="kv-k">Process</div><div class="kv-v">'+copyable(id.process||'Unknown')+'</div>';
  h+='<div class="kv-k">Command Line</div><div class="kv-v"><div class="code">'+esc(id.cmdline||'N/A')+'</div></div>';
  h+='<div class="kv-k">SHA1</div><div class="kv-v">'+sha1Html+'</div>';
  h+='<div class="kv-k">Signed</div><div class="kv-v">'+signHtml+'</div>';
  h+='<div class="kv-k">Publisher</div><div class="kv-v">'+pubHtml+'</div>';
  h+='<div class="kv-k">Parent</div><div class="kv-v"><div class="code">'+esc(id.parent||'N/A')+'</div></div>';
  h+='<div class="kv-k">User</div><div class="kv-v">'+esc(id.user||'N/A')+'</div>';
  h+='<div class="kv-k">Agent UUID</div><div class="kv-v">'+copyable(id.agent_uuid||'N/A')+'</div>';
  var slId=id.storyline_id||'';
  h+='<div class="kv-k">Storyline ID</div><div class="kv-v">'+(slId?copyable(slId):'<span style="color:var(--dim);font-size:12px">Not available'+(isSDL?' (SDL format)':'')+'</span>')+'</div>';
  if(id.is_electron)h+='<div class="kv-k">Electron App</div><div class="kv-v"><span class="badge b-info">ELECTRON</span> '+esc((id.electron_meta||{}).app_name||'')+'</div>';
  var av=id.attack_vector||{};
  if(av.severity&&av.severity!=='FAIBLE')h+='<div class="kv-k">Attack Vector</div><div class="kv-v">'+sevBadge(av.severity)+' '+esc(av.description||'')+'</div>';
  h+='</div>';
  var chain=id.execution_chain||[];
  if(chain.length>0){
    h+='<div style="margin-top:16px"><div class="chart-title">Execution Chain</div><div class="ptree">';
    chain.forEach(function(c,i){
      var indent=new Array(i*4+1).join('&nbsp;');
      var arrow=i>0?'&#9492;&#9472; ':'&#9881; ';
      h+='<div class="pnode">'+indent+arrow+'<span class="pname">'+esc(c.level)+'</span> <span class="pcmd">'+esc((c.cmdline||'').substring(0,200))+'</span></div>';
    });
    h+='</div></div>';
  }
  return h;
}

function renderTimeline(){
  var tl=DATA.timeline||{};
  var dur=tl.duration_seconds||0;
  var durStr=dur>=60?Math.floor(dur/60)+'m '+Math.floor(dur%60)+'s':Math.floor(dur)+'s';
  var h='<div class="kv-grid">';
  h+='<div class="kv-k">Period</div><div class="kv-v">'+esc(tl.start||'N/A')+' \u2192 '+esc(tl.end||'N/A')+' ('+durStr+')</div>';
  h+='<div class="kv-k">Total Events</div><div class="kv-v">'+(DATA.metrics||{}).total_events+'</div>';
  h+='</div>';
  var phases=tl.phases||[];
  if(phases.length>0){
    h+='<div class="chart-title" style="margin-top:16px">Activity Phases</div><div class="tl-phases">';
    phases.forEach(function(p){
      h+='<div class="tl-phase"><div class="tl-phase-name">'+esc(p.name)+'</div>';
      h+='<div class="tl-phase-time">'+esc(p.start||'')+' \u2192 '+esc(p.end||'')+'</div>';
      h+='<div style="color:var(--dim);font-size:11px;margin-top:2px">'+p.event_count+' events</div></div>';
    });
    h+='</div>';
  }
  return h;
}

function renderIndicators(){
  var indicators=DATA.behavioral_indicators||[];
  if(indicators.length===0)return '<p style="color:var(--dim)">No behavioral indicators detected.</p>';
  var sev=DATA.severity_distribution||{};
  var h='<input type="text" class="search-box" placeholder="Search indicators..." oninput="filterIndicators(this.value)">';
  h+='<div id="indicators-list">';
  indicators.forEach(function(ind){
    var sc=sevClass(ind.severity);var isFP=ind.false_positive===true;
    h+='<div class="ind-card'+(isFP?' fp':'')+'">';
    h+='<div class="ind-hdr">'+sevBadge(ind.severity)+' <strong>'+esc(ind.name||'Unknown')+'</strong>';
    if(isFP)h+=' <span class="badge b-fp">FALSE POSITIVE</span>';
    if(ind.occurrences>1)h+=' <span class="sb">x'+ind.occurrences+'</span>';
    if(ind.category)h+=' <span style="margin-left:auto;font-size:11px;color:var(--dim)">'+esc(ind.category)+'</span>';
    h+='</div><div class="ind-body">';
    if(ind.description)h+='<div class="ind-row"><span class="ind-lbl">Description</span><span class="ind-val">'+esc(ind.description)+'</span></div>';
    if(ind.context)h+='<div class="ind-row"><span class="ind-lbl">Context</span><span class="ind-val">'+esc(ind.context)+'</span></div>';
    if(ind.explanation)h+='<div class="ind-row"><span class="ind-lbl">Analysis</span><span class="ind-val">'+esc(ind.explanation)+'</span></div>';
    var mt=ind.mitre_techniques||[];
    if(mt.length>0){
      h+='<div class="ind-row"><span class="ind-lbl">MITRE</span><span class="ind-val mitre-grid">';
      mt.forEach(function(t){h+='<span class="mitre-badge">'+esc(t.id)+' \u2014 '+esc(t.name||'')+'</span>';});
      h+='</span></div>';
    }
    if(ind.timestamp)h+='<div class="ind-row"><span class="ind-lbl">Timestamp</span><span class="ind-val" style="color:var(--dim);font-size:12px">'+esc(ind.timestamp)+'</span></div>';
    h+='</div></div>';
  });
  h+='</div>';
  return h;
}
function filterIndicators(q){q=q.toLowerCase();document.querySelectorAll('.ind-card').forEach(function(c){c.style.display=c.textContent.toLowerCase().indexOf(q)>=0?'':'none';});}

function renderMitre(){
  var ma=DATA.mitre_attack||{};
  var tactics=ma.tactics||[],techniques=ma.techniques||[];
  var h='';
  if(tactics.length>0){
    h+='<div class="chart-title">Tactics Covered</div><div class="mitre-grid" style="margin-bottom:16px">';
    tactics.forEach(function(t){h+='<span class="tactic-badge">'+esc(t)+'</span>';});
    h+='</div>';
  }
  if(techniques.length>0){
    h+='<div class="chart-title">Techniques</div>';
    h+='<table><thead><tr><th>Technique ID</th><th>Name</th></tr></thead><tbody>';
    techniques.forEach(function(t){
      h+='<tr><td><code style="color:var(--purple)">'+esc(t.id)+'</code></td><td>'+esc(t.name||'')+'</td></tr>';
    });
    h+='</tbody></table>';
  }
  return h||'<p style="color:var(--dim)">No MITRE ATT&CK data.</p>';
}

function renderAttackChains(){
  var chains=DATA.attack_chains||[];
  if(!chains.length) return '<p style="color:var(--dim)">No attack chains detected.</p>';
  var h='<div style="display:flex;flex-wrap:wrap;gap:8px;">';
  chains.forEach(function(c){
    h+='<span class="pill crit">'+esc(c)+'</span>';
  });
  h+='</div>';
  return h;
}

function renderScripts(){
  var sc=DATA.scripts||{},summaries=sc.summaries||[],findings=sc.findings||[];
  var h='';
  if(summaries.length>0){
    h+='<div style="margin-bottom:14px;color:var(--dim)">'+summaries.length+' script capture(s)</div>';
    summaries.slice(0,8).forEach(function(s,i){
      h+='<div style="margin-bottom:14px"><strong>'+esc(s.app||'Script '+(i+1))+'</strong> ('+esc(s.length||0)+' chars)';
      h+='<div class="code" style="margin-top:6px;max-height:300px;overflow-y:auto">'+esc(s.preview||'')+'</div></div>';
    });
  }
  if(findings.length>0){
    h+='<div class="chart-title" style="margin-top:16px">Malicious Patterns ('+findings.length+')</div>';
    findings.forEach(function(f){
      h+='<div class="ind-card" style="margin-bottom:8px"><div class="ind-hdr">'+sevBadge(f.severity||'MOYEN')+' <strong>'+esc(f.description||'Finding')+'</strong>';
      if(f.mitre)h+=' <span class="mitre-badge" style="margin-left:auto">'+esc(f.mitre)+'</span>';
      h+='</div>';
      if(f.context)h+='<div class="ind-body"><div class="code" style="border-color:var(--red);max-height:300px;overflow-y:auto">'+esc(f.context)+'</div></div>';
      h+='</div>';
    });
  }
  return h||'<p style="color:var(--dim)">No script data.</p>';
}

function renderModules(){
  var mod=DATA.modules||{},suspicious=mod.suspicious||[];
  var h='<div style="color:var(--dim);margin-bottom:10px">Total loaded: <strong style="color:var(--text)">'+(mod.total||0)+'</strong> &mdash; Suspicious: <strong style="color:'+(suspicious.length>0?'var(--high)':'var(--text)') +'">'+ suspicious.length +'</strong></div>';
  if(suspicious.length>0){
    h+='<table><thead><tr><th>Severity</th><th>Module</th><th>Description</th><th>Path</th></tr></thead><tbody>';
    suspicious.forEach(function(m){
      h+='<tr><td>'+sevBadge(m.severity||'MOYEN')+'</td><td>'+esc(m.name||m.module||'')+'</td><td style="font-size:12px">'+esc(m.description||m.reason||'')+'</td><td style="font-family:var(--font-mono);font-size:11px">'+esc(m.path||'')+'</td></tr>';
    });
    h+='</tbody></table>';
  }
  return h;
}

function renderNetwork(){
  var net=DATA.network||{},ext=net.external_connections||[],dns=net.dns_queries||[];
  var c2=net.c2_beacons||[],ua=net.suspicious_user_agents||[],listeners=net.listeners||[];
  var h='';
  if(c2.length>0){
    h+='<div class="alert-box danger" style="margin-bottom:14px"><span style="font-size:18px">&#9888;</span><div><strong>Potential C2 Beacons</strong><br>';
    c2.forEach(function(b){h+='<span style="font-family:var(--font-mono);font-size:12px">'+esc(b.dst_ip||b.ip||JSON.stringify(b))+'</span><br>';});
    h+='</div></div>';
  }
  if(ext.length>0){
    h+='<div class="chart-title">External Connections ('+ext.length+')</div>';
    h+='<div class="tbl-wrap"><table><thead><tr><th>IP</th><th>Port</th><th>Owner / Geo</th><th>Direction</th></tr></thead><tbody>';
    ext.forEach(function(c){
      var geo=c.geo||{};var geoStr=geo.country?esc(geo.country)+'/'+esc(geo.city||'')+(geo.org?' ('+esc(geo.org)+')':''):'';
      var domain=c.domain?esc(c.domain)+' ':'';
      var isUnk=!geo.country&&!c.domain;
      h+='<tr><td>'+(isUnk?'<span class="ip-unk">':'<span class="ip-ok">')+copyable(c.dst_ip||c.ip||'')+'</span>'+(isUnk?'<span class="unk-badge">unknown</span>':'')+'</td>';
      h+='<td>'+esc(c.dst_port||c.port||'')+'</td>';
      h+='<td>'+domain+geoStr+'</td>';
      h+='<td>'+esc(c.direction||c.event_type||'')+'</td></tr>';
    });
    h+='</tbody></table></div>';
  }
  if(dns.length>0){
    h+='<div class="chart-title" style="margin-top:16px">DNS Queries ('+dns.length+')</div>';
    h+='<div class="tbl-wrap"><table><thead><tr><th>Status</th><th>Request</th></tr></thead><tbody>';
    dns.forEach(function(q){
      var req=q.request||q.req||'';var ok=q.resolved!==undefined?q.resolved:q.ok;
      h+='<tr><td><span class="badge '+(ok?'b-low':'b-critical')+'">'+(ok?'OK':'FAIL')+'</span></td>';
      h+='<td style="font-family:var(--font-mono);font-size:12px">'+copyable(req)+'</td></tr>';
    });
    h+='</tbody></table></div>';
  }
  if(ua.length>0){
    h+='<div class="chart-title" style="margin-top:16px">Suspicious User Agents</div>';
    ua.forEach(function(u){h+='<div class="code" style="margin-bottom:4px">'+esc(typeof u==='string'?u:JSON.stringify(u))+'</div>';});
  }
  if(listeners.length>0){
    h+='<div class="chart-title" style="margin-top:16px">Listeners</div>';
    listeners.forEach(function(l){h+='<div class="code" style="margin-bottom:4px">'+esc(typeof l==='string'?l:JSON.stringify(l))+'</div>';});
  }
  return h||'<p style="color:var(--dim)">No network data.</p>';
}

function renderProcessTree(){
  var pt=DATA.process_tree||{},root=pt.root||{},children=pt.children||[];
  if(!root.cmdline&&children.length===0)return '<p style="color:var(--dim)">No process tree data.</p>';
  var h='<div class="ptree">';
  var rName=(root.display_name||'').replace(/\x00/g,'').trim()||(root.cmdline||'').split(/[\s\\\/]+/).pop()||'Root';
  var rSigned=root.signed||'';
  h+='<div class="pnode">&#9881; <span class="pname">'+esc(rName)+'</span>';
  h+=' '+(rSigned==='signed'?'<span class="b-signed">signed</span>':'<span class="b-unsigned">'+esc(rSigned||'unknown')+'</span>');
  if(root.publisher)h+=' <span class="ppub">['+esc(root.publisher)+']</span>';
  if(root.sha1)h+='<br>&nbsp;&nbsp;<span class="psha">SHA1: '+copyable(root.sha1)+'</span>';
  if(root.cmdline)h+='<br>&nbsp;&nbsp;<span class="pcmd">'+esc((root.cmdline||'').substring(0,120))+'</span>';
  h+='</div>';
  children.slice(0,30).forEach(function(c){
    var cName=(c.display_name||'').replace(/\x00/g,'').trim()||(c.cmdline||'').split(/[\s\\\/]+/).pop()||'child';
    var cSigned=c.signed||'';
    h+='<div class="pnode">&nbsp;&nbsp;&#9500;&#9472; <span class="pname">'+esc(cName)+'</span>';
    h+=' '+(cSigned==='signed'?'<span class="b-signed">signed</span>':'<span class="b-unsigned">'+esc(cSigned||'unknown')+'</span>');
    if(c.publisher)h+=' <span class="ppub">['+esc(c.publisher)+']</span>';
    if(c.sha1)h+='<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="psha">SHA1: '+copyable(c.sha1)+'</span>';
    if(c.cmdline)h+='<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span class="pcmd">'+esc((c.cmdline||'').substring(0,120))+'</span>';
    h+='</div>';
  });
  if(children.length>30)h+='<div style="color:var(--dim);padding:6px">&hellip; and '+(children.length-30)+' more child processes</div>';
  h+='</div>';
  return h;
}

function renderFiles(){
  var f=DATA.files||{},summary=f.summary||{},topDirs=f.top_dirs||[],suspicious=f.suspicious||[];
  var h='';
  var sumEntries=Object.entries(summary);
  if(sumEntries.length>0){
    h+='<table><thead><tr><th>Operation</th><th>Count</th></tr></thead><tbody>';
    sumEntries.forEach(function(e){h+='<tr><td>'+esc(e[0])+'</td><td>'+esc(e[1])+'</td></tr>';});
    h+='</tbody></table>';
  }
  if(topDirs.length>0){
    h+='<div class="chart-title" style="margin-top:16px">Top Directories</div>';
    h+='<table><thead><tr><th>Directory</th><th>Count</th></tr></thead><tbody>';
    topDirs.forEach(function(d){
      var name=Array.isArray(d)?d[0]:(d.dir||d.path||'');
      var count=Array.isArray(d)?d[1]:(d.count||0);
      h+='<tr><td style="font-family:var(--font-mono);font-size:11px">'+esc(name)+'</td><td>'+esc(count)+'</td></tr>';
    });
    h+='</tbody></table>';
  }
  if(suspicious.length>0){
    h+='<div class="chart-title" style="margin-top:16px">Suspicious Files</div>';
    suspicious.forEach(function(s){
      h+='<div class="alert-box danger" style="margin-bottom:6px"><div style="font-family:var(--font-mono);font-size:12px;word-break:break-all">'+esc(s.path||'');
      if(s.sha1)h+='<br>SHA1: '+copyable(s.sha1);
      h+='</div></div>';
    });
  }
  return h||'<p style="color:var(--dim)">No file activity data.</p>';
}

function renderRegistry(){
  var r=DATA.registry||{},summary=r.summary||{},persistence=r.persistence_hits||[];
  var h='';
  var sumEntries=Object.entries(summary);
  if(sumEntries.length>0){
    h+='<table><thead><tr><th>Hive</th><th>Count</th></tr></thead><tbody>';
    sumEntries.forEach(function(e){h+='<tr><td style="font-family:var(--font-mono);font-size:12px">'+esc(e[0])+'</td><td>'+esc(e[1])+'</td></tr>';});
    h+='</tbody></table>';
  }
  if(persistence.length>0){
    h+='<div class="chart-title" style="margin-top:16px">Persistence Keys ('+persistence.length+')</div>';
    persistence.forEach(function(p){
      h+='<div class="alert-box danger" style="margin-bottom:6px"><span style="font-size:14px">&#128274;</span><div>';
      h+='<strong>'+esc(p.label||p.key||p.rule||p.match||'Persistence')+'</strong>';
      h+='<br><span style="font-family:var(--font-mono);font-size:11px;color:var(--dim)">'+esc(p.key||p.path||'')+'</span>';
      if(p.value)h+='<br><span style="font-family:var(--font-mono);font-size:11px">'+esc(p.value)+'</span>';
      h+='</div></div>';
    });
  }
  return h||'<p style="color:var(--dim)">No registry data.</p>';
}

function renderVirusTotal(){
  var vt=DATA.virustotal||[];
  if(vt.length===0)return '<p style="color:var(--dim)">VirusTotal API not enabled \u2014 run with --vt-key YOUR_KEY to enable hash checking</p>';
  var h='<table><thead><tr><th>Role</th><th>Name</th><th>SHA1</th><th>Result</th></tr></thead><tbody>';
  vt.forEach(function(v){
    var r=v.result||{};
    var det=r.positives||r.malicious||0,total=r.total||0;
    var resHtml;
    if(!r||Object.keys(r).length===0)resHtml='<span style="color:var(--dim)">Not found</span>';
    else if(det>0)resHtml='<span style="color:var(--critical);font-weight:700">'+det+'/'+total+' engines</span>'+(r.threat_type?' <span class="badge b-critical">'+esc(r.threat_type)+'</span>':'');
    else resHtml='<span style="color:var(--low)">0/'+total+' clean</span>';
    h+='<tr><td>'+esc(v.role||'')+'</td><td>'+esc(v.name||'')+'</td><td style="font-family:var(--font-mono);font-size:11px">'+copyable(v.sha1||'')+'</td><td>'+resHtml+'</td></tr>';
  });
  h+='</tbody></table>';
  return h;
}

function renderSigma(){
  var matches=DATA.sigma_matches||[];
  if(matches.length===0)return '<p style="color:var(--dim)">No Sigma rule matched.</p>';
  var h='<input type="text" class="search-box" placeholder="Search sigma rules..." oninput="filterByClass(this,\'.sigma-card\')">';
  matches.slice(0,30).forEach(function(m){
    var level=m.level||m.severity||'info';
    var scls={critical:'b-critical',high:'b-high',medium:'b-medium',low:'b-low',informational:'b-info'};
    var bcls=scls[level.toLowerCase()]||'b-info';
    h+='<div class="sigma-card" style="border:1px solid var(--border);border-radius:7px;margin-bottom:8px;overflow:hidden">';
    h+='<div style="background:var(--surface2);padding:8px 12px;display:flex;align-items:center;gap:10px">';
    h+='<span class="badge '+bcls+'">'+esc(level)+'</span>';
    h+='<strong>'+esc(m.title||m.name||'Rule')+'</strong>';
    if(m.category)h+='<span style="margin-left:auto;color:var(--dim);font-size:11px">'+esc(m.category)+'</span>';
    h+='</div><div style="padding:8px 12px">';
    if(m.description)h+='<div style="font-size:12px;color:var(--dim);margin-bottom:4px">'+esc((m.description||'').substring(0,200))+'</div>';
    var tags=m.tags||[];
    if(tags.length>0){h+='<div class="mitre-grid">';tags.slice(0,3).forEach(function(t){h+='<span class="mitre-badge" style="font-size:11px">'+esc(t)+'</span>';});h+='</div>';}
    h+='</div></div>';
  });
  if(matches.length>30)h+='<div style="color:var(--dim);font-size:12px;margin-top:8px">&hellip; and '+(matches.length-30)+' more match(es)</div>';
  return h;
}

function renderProcessGraph(){
  var pg=DATA.process_graph||{};
  if(!pg.available)return '<p style="color:var(--dim)">NetworkX not available.</p>';
  var anomalies=pg.anomalies||[];
  if(anomalies.length===0)return '<p style="color:var(--dim)">No graph anomaly detected.</p>';
  var h='';
  anomalies.forEach(function(a){
    var scls={CRITIQUE:'b-critical',ELEVE:'b-high',MOYEN:'b-medium'};
    var bcls=scls[a.severity]||'b-info';
    h+='<div style="display:flex;gap:10px;align-items:flex-start;padding:9px 12px;border-bottom:1px solid var(--border)">';
    h+='<span class="badge '+bcls+'">'+esc(a.type||a.severity||'')+'</span>';
    h+='<div style="font-size:13px">'+esc(a.description||JSON.stringify(a))+'</div></div>';
  });
  return '<div style="border:1px solid var(--border);border-radius:7px;overflow:hidden">'+h+'</div>';
}

function renderStatistical(){
  var sa=DATA.statistical_analysis||{},stats=sa.stats||{},outliers=sa.outliers||[],afterHours=sa.after_hours||[];
  var h='';
  var kvHtml='';
  if(stats.cmd_len)kvHtml+='<div class="kv-k">Cmdline length</div><div class="kv-v">mean='+esc(stats.cmd_len.mean)+' std='+esc(stats.cmd_len.std)+'</div>';
  if(stats.cmd_entropy)kvHtml+='<div class="kv-k">Cmdline entropy</div><div class="kv-v">mean='+esc(stats.cmd_entropy.mean)+' std='+esc(stats.cmd_entropy.std)+' bits</div>';
  if(kvHtml)h+='<div class="kv-grid" style="margin-bottom:14px">'+kvHtml+'</div>';
  if(afterHours.length>0){
    h+='<div class="chart-title">After-hours Events ('+afterHours.length+')</div>';
    h+='<table><thead><tr><th>Timestamp</th><th>Event Type</th></tr></thead><tbody>';
    afterHours.slice(0,5).forEach(function(e){
      h+='<tr><td style="font-family:var(--font-mono);font-size:11px;color:var(--dim)">'+esc(e.timestamp_raw||e.timestamp||'')+'</td><td style="font-size:12px">'+esc(e.event_type||'')+'</td></tr>';
    });
    h+='</tbody></table>';
  }
  if(outliers.length>0){
    h+='<div class="chart-title" style="margin-top:14px">IsolationForest Outliers ('+outliers.length+')</div>';
    h+='<table><thead><tr><th>Score</th><th>Event</th><th>Command</th><th>Entropy</th></tr></thead><tbody>';
    outliers.slice(0,10).forEach(function(o){
      h+='<tr><td style="font-family:var(--font-mono);font-size:11px;color:var(--red)">'+esc(o.score||'?')+'</td>';
      h+='<td style="font-size:12px">'+esc(o.event_type||'')+'</td>';
      h+='<td style="font-family:var(--font-mono);font-size:11px;color:var(--dim)">'+esc((o.cmd||'').substring(0,80))+'</td>';
      h+='<td style="font-size:11px;color:var(--dim)">'+esc(o.entropy||'?')+'</td></tr>';
    });
    h+='</tbody></table>';
  } else if(sa.has_pyod){
    h+='<div class="alert-box success">IsolationForest: No outlier detected.</div>';
  } else {
    h+='<div class="alert-box info">pyod not installed &mdash; install with: pip install pyod</div>';
  }
  var rare=stats.rare_pairs||[];
  if(rare.length>0)h+='<div style="font-size:12px;color:var(--dim);margin-top:8px"><strong>Rare parent\u2192child pairs:</strong> '+esc(rare.slice(0,8).join(', '))+'</div>';
  return h||'<p style="color:var(--dim)">No statistical anomaly detected.</p>';
}

function renderYara(){
  var hits=DATA.yara_matches||[];
  if(hits.length===0)return '<p style="color:var(--dim)">No YARA rule matched.</p>';
  var h='';
  var scls={CRITIQUE:'b-critical',ELEVE:'b-high'};
  hits.slice(0,20).forEach(function(hr){
    var bcls=scls[hr.severity]||'b-medium';
    var tagHtml=(hr.tags&&hr.tags.length)?'<span style="font-size:11px;color:var(--dim)">Tags: '+esc(hr.tags.slice(0,5).join(', '))+'</span>':'';
    h+='<div style="border:1px solid var(--border);border-radius:7px;margin-bottom:8px;overflow:hidden">';
    h+='<div style="background:var(--surface2);padding:8px 12px;display:flex;align-items:center;gap:10px">';
    h+='<span class="badge '+bcls+'">'+esc(hr.severity||'MOYEN')+'</span>';
    h+='<strong>'+esc(hr.rule||hr.name||'Rule')+'</strong>';
    h+='<span style="margin-left:auto;color:var(--dim);font-size:11px">'+esc(hr.context||'')+'</span></div>';
    h+='<div style="padding:8px 12px"><div class="code" style="font-size:11px">'+esc((hr.preview||'').substring(0,120))+'</div>'+tagHtml+'</div></div>';
  });
  if(hits.length>20)h+='<div style="color:var(--dim);font-size:12px;margin-top:8px">&hellip; and '+(hits.length-20)+' more</div>';
  return h;
}

function renderAttackEnrichment(){
  var me=DATA.mitre_enrichment||{},groups=(me.groups||[]).filter(function(g){return (typeof g==='string'?g:(g.id||''))+(typeof g==='object'?(g.name||''):'');}),techniques=me.techniques||[];
  var h='';
  if(groups.length>0){
    h+='<div class="chart-title">Threat Groups Using These Techniques ('+groups.length+')</div><div style="display:flex;flex-wrap:wrap;gap:7px;margin-bottom:16px">';
    groups.slice(0,8).forEach(function(g){
      var gid=typeof g==='string'?g:(g.id||'');var gname=typeof g==='object'?(g.name||''):'';
      h+='<span style="background:var(--orange-l);color:var(--orange);border:1px solid #fed7aa;padding:3px 10px;border-radius:6px;font-size:12px;font-weight:600">'+esc(gid)+(gname?' \u2014 '+esc(gname):'')+'</span>';
    });
    h+='</div>';
  }
  techniques.slice(0,10).forEach(function(t){
    var mitHtml='';
    if(t.mitigations&&t.mitigations.length){
      mitHtml='<div style="margin-top:6px">';
      t.mitigations.filter(function(m){return (m.id||'')+(m.name||'');}).slice(0,3).forEach(function(m){
        var mid=typeof m==='string'?m:(m.id||'');var mname=typeof m==='object'?(m.name||''):'';
        mitHtml+='<span style="background:var(--green-l);color:var(--green-d);border:1px solid #bbf7d0;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;margin-right:5px">'+esc(mid)+' '+esc(mname)+'</span>';
      });
      mitHtml+='</div>';
    }
    var grpHtml='';
    var validGroups=(t.groups||[]).filter(function(g){return (typeof g==='string'?g:(g.id||''))+(typeof g==='object'?(g.name||''):'');});
    if(validGroups.length){
      var grps=validGroups.slice(0,3).map(function(g){var gid=typeof g==='string'?g:(g.id||'');var gn=typeof g==='object'?(g.name||''):'';return gid+(gn?' ('+gn+')':'');}).join(', ');
      grpHtml='<div style="font-size:11px;color:var(--orange);margin-top:4px">Groups: '+esc(grps)+'</div>';
    }
    var detHtml='';
    if(t.detection)detHtml='<div style="margin-top:6px;padding:8px;background:var(--surface3);border-radius:4px;font-size:11px;color:var(--text)">'+esc((t.detection||'').substring(0,300))+'</div>';
    h+='<div style="border:1px solid var(--border);border-radius:7px;margin-bottom:8px;overflow:hidden">';
    h+='<div style="background:var(--surface2);padding:8px 12px;display:flex;align-items:center;gap:10px">';
    h+='<code style="color:var(--purple)">'+esc(t.id||'')+'</code>';
    h+='<strong>'+esc(t.name||'')+'</strong>';
    if(t.tactic)h+='<span class="tactic-badge" style="margin-left:auto">'+esc(t.tactic)+'</span>';
    h+='</div><div style="padding:8px 12px">'+detHtml+mitHtml+grpHtml+'</div></div>';
  });
  return h||'<p style="color:var(--dim)">ATT&amp;CK bundle not loaded &mdash; run --update first.</p>';
}

function renderIOC(){
  var iocs=DATA.ioc_extraction||{};
  var kindLabels={urls:'URLs',ips:'IP Addresses',hashes:'Hashes (SHA1)',emails:'Emails',file_hashes:'File & Process Hashes'};
  var total=0;
  Object.values(iocs).forEach(function(v){if(Array.isArray(v))total+=v.length;});
  if(total===0)return '<p style="color:var(--dim)">No IOCs extracted.</p>';
  var h='';
  Object.entries(iocs).forEach(function(e){
    var kind=e[0],items=e[1];
    if(!Array.isArray(items)||items.length===0)return;
    h+='<div style="margin-bottom:14px"><div class="chart-title">'+esc(kindLabels[kind]||kind)+' ('+items.length+')</div>';
    items.slice(0,15).forEach(function(item){
      if(typeof item==='object'&&item.sha1){
        h+='<div style="font-family:var(--font-mono);font-size:12px;padding:4px 8px;background:var(--red-l);border-radius:4px;margin-bottom:3px;display:flex;gap:8px;align-items:center;color:var(--red-d)" class="copyable" data-copy="'+esc(item.sha1)+'"><span style="flex:1;word-break:break-all">'+esc(item.sha1)+'</span><span style="color:var(--dim);font-size:11px;white-space:nowrap">'+esc(item.name||'')+'</span></div>';
      } else {
        var val=typeof item==='string'?item:(item.value||item.ioc||JSON.stringify(item));
        h+='<div style="font-family:var(--font-mono);font-size:12px;padding:4px 8px;background:var(--red-l);border-radius:4px;margin-bottom:3px;word-break:break-all;color:var(--red-d)" class="copyable" data-copy="'+esc(val)+'">'+esc(val)+'</div>';
      }
    });
    if(items.length>15)h+='<div style="color:var(--dim);font-size:11px">&hellip; and '+(items.length-15)+' more</div>';
    h+='</div>';
  });
  return h;
}

function renderThreatIntelligence(){
  var ti=DATA.threat_intelligence||{};
  var mb=ti.malwarebazaar||[],oh=ti.otx_hashes||[],oi=ti.otx_ips||[],od=ti.otx_domains||[],sh=ti.shodan||[];
  var total=mb.length+oh.length+oi.length+od.length+sh.length;
  var enabled=ti._enabled||[];
  if(enabled.length===0)return '<p style="color:var(--dim)">Threat intelligence APIs not enabled \u2014 use --mb (MalwareBazaar), --otx-key KEY (OTX), --shodan-key KEY (Shodan)</p>';
  if(total===0)return '<p style="color:var(--green)">Threat intelligence APIs queried ('+enabled.join(', ')+') \u2014 no known malicious indicators found.</p>';
  var h='';
  if(mb.length>0){
    h+='<div class="chart-title">MalwareBazaar ('+mb.length+' hit(s))</div>';
    mb.forEach(function(m){
      h+='<div class="alert-box danger" style="margin-bottom:8px"><span style="font-size:18px">&#9888;</span><div>';
      h+='<strong>['+esc(m.role)+'] '+esc(m.name)+'</strong><br>';
      h+='<span style="font-family:var(--font-mono);font-size:11px">SHA1: '+copyable(m.sha1||'')+'</span><br>';
      if(m.signature)h+='Signature: <span style="color:var(--critical);font-weight:700">'+esc(m.signature)+'</span> | ';
      if(m.file_type)h+='Type: '+esc(m.file_type)+' | ';
      if(m.first_seen)h+='First seen: '+esc(m.first_seen);
      if(m.tags&&m.tags.length)h+='<br>Tags: '+esc(m.tags.slice(0,5).join(', '));
      h+='</div></div>';
    });
  }
  if(oh.length>0){
    h+='<div class="chart-title" style="margin-top:14px">OTX Hash Intelligence ('+oh.length+' hit(s))</div>';
    oh.forEach(function(o){
      h+='<div class="alert-box warn" style="margin-bottom:6px"><span>&#9679;</span><div>';
      h+='SHA1: '+copyable(o.sha1||'')+' — found in <strong>'+o.pulse_count+'</strong> pulse(s)';
      if(o.malware_families&&o.malware_families.length)h+='<br>Families: <span style="color:var(--orange)">'+esc(o.malware_families.slice(0,5).join(', '))+'</span>';
      h+='</div></div>';
    });
  }
  if(oi.length>0){
    h+='<div class="chart-title" style="margin-top:14px">OTX IP Intelligence ('+oi.length+' hit(s))</div>';
    h+='<table><thead><tr><th>IP</th><th>Pulses</th><th>Country</th></tr></thead><tbody>';
    oi.forEach(function(o){h+='<tr><td style="font-family:var(--font-mono)">'+copyable(o.ip||'')+'</td><td>'+esc(o.pulse_count)+'</td><td>'+esc(o.country||'')+'</td></tr>';});
    h+='</tbody></table>';
  }
  if(od.length>0){
    h+='<div class="chart-title" style="margin-top:14px">OTX Domain Intelligence ('+od.length+' hit(s))</div>';
    h+='<table><thead><tr><th>Domain</th><th>Pulses</th></tr></thead><tbody>';
    od.forEach(function(o){h+='<tr><td style="font-family:var(--font-mono)">'+copyable(o.domain||'')+'</td><td>'+esc(o.pulse_count)+'</td></tr>';});
    h+='</tbody></table>';
  }
  if(sh.length>0){
    h+='<div class="chart-title" style="margin-top:14px">Shodan Intelligence ('+sh.length+' hit(s))</div>';
    sh.forEach(function(s){
      h+='<div style="border:1px solid var(--border);border-radius:7px;padding:10px 14px;margin-bottom:8px">';
      h+='<strong style="font-family:var(--font-mono)">'+copyable(s.ip||'')+'</strong>';
      if(s.org)h+=' — '+esc(s.org);
      if(s.country)h+=' ('+esc(s.country)+')';
      if(s.ports&&s.ports.length)h+='<br><span style="font-size:12px;color:var(--dim)">Ports: '+esc(s.ports.slice(0,10).join(', '))+'</span>';
      if(s.vulns&&s.vulns.length)h+='<br><span style="font-size:12px;color:var(--critical);font-weight:700">Vulns: '+esc(s.vulns.join(', '))+'</span>';
      if(s.hostnames&&s.hostnames.length)h+='<br><span style="font-size:11px;color:var(--dim)">'+esc(s.hostnames.slice(0,3).join(', '))+'</span>';
      h+='</div>';
    });
  }
  return h;
}

function renderLsass(){
  var hits=DATA.lsass||[];
  if(hits.length===0)return '<p style="color:var(--dim)">No LSASS access detected.</p>';
  var h='<div class="alert-box danger" style="margin-bottom:14px"><span style="font-size:18px">&#9888;</span><strong>LSASS Access Detected &mdash; Potential Credential Dumping</strong></div>';
  h+='<table><thead><tr><th>Source</th><th>Access</th><th>Timestamp</th></tr></thead><tbody>';
  hits.forEach(function(hr){
    h+='<tr><td>'+esc(hr.source||hr.process||'')+'</td><td>'+esc(hr.access||hr.access_mask||'')+'</td><td>'+esc(hr.timestamp||'')+'</td></tr>';
  });
  h+='</tbody></table>';
  return h;
}

function renderCmdline(){
  var cmd=DATA.cmdline_analysis||{},findings=cmd.findings||[],entropy=cmd.high_entropy||[];
  var h='';
  if(findings.length>0){
    findings.forEach(function(f){
      h+='<div class="ind-card" style="margin-bottom:8px"><div class="ind-hdr">'+sevBadge(f.severity||'INFO')+' <strong>'+esc(f.description||f.name||'')+'</strong></div>';
      if(f.cmdline)h+='<div class="ind-body"><div class="code">'+esc(f.cmdline)+'</div></div>';
      h+='</div>';
    });
  }
  if(entropy.length>0){
    h+='<div class="chart-title" style="margin-top:16px">High Entropy Processes</div>';
    entropy.forEach(function(e){h+='<div class="code" style="margin-bottom:4px">'+esc(e.cmdline||e.process||JSON.stringify(e))+'</div>';});
  }
  return h||'<p style="color:var(--dim)">No command line findings.</p>';
}

function renderTemporal(){
  var seqs=DATA.temporal_sequences||[];
  if(seqs.length===0)return '<p style="color:var(--dim)">No suspicious temporal sequences.</p>';
  var h='';
  seqs.forEach(function(s){
    h+='<div class="alert-box info" style="margin-bottom:6px"><span>&#9200;</span><div>'+esc(typeof s==='string'?s:s.description||JSON.stringify(s))+'</div></div>';
  });
  return h;
}

function renderTasks(){
  var tasks=DATA.tasks||[];
  if(tasks.length===0)return '<p style="color:var(--dim)">No scheduled tasks detected.</p>';
  var h='<table><thead><tr><th>Name</th><th>Command</th><th>Details</th></tr></thead><tbody>';
  tasks.forEach(function(t){
    h+='<tr><td>'+esc(t.name||t.task_name||'')+'</td><td class="code" style="border:none;padding:6px">'+esc(t.command||t.cmdline||'')+'</td><td>'+esc(t.details||t.trigger||'')+'</td></tr>';
  });
  h+='</tbody></table>';
  return h;
}

// ── FINAL VERDICT & DIAGNOSIS SECTION ──
function renderDiagnosis(){
  var v=DATA.verdict||{};
  var score=v.score||0,maxS=20;
  var scoreClass=score>=16?'critical':score>=12?'high':score>=8?'medium':score>=4?'low':'low';
  var gc={critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#22c55e'}[scoreClass]||'#3b82f6';
  var tp=v.evidence_tp||[],fp=v.evidence_fp||[],obs=v.observations||[],recs=v.recommendations||[];

  var h='<div style="display:flex;align-items:center;gap:24px;flex-wrap:wrap;margin-bottom:20px">';
  // Mini gauge
  h+='<svg viewBox="0 0 100 80" width="100" height="80">';
  h+='<path d="M10.4,69.6 A42,42 0 1,1 89.6,69.6" fill="none" stroke="var(--border)" stroke-width="8" stroke-linecap="round" opacity="0.5"/>';
  var pct=Math.min(score/maxS,1),R=42,cx=50,cy=52,sa=-220,sw=260;
  var rad=function(a){return a*Math.PI/180;};
  var spt=[cx+R*Math.cos(rad(sa)),cy+R*Math.sin(rad(sa))];
  var ept=[cx+R*Math.cos(rad(sa+sw*pct)),cy+R*Math.sin(rad(sa+sw*pct))];
  var lg=sw*pct>180?1:0;
  if(pct>0)h+='<path d="M'+spt[0]+','+spt[1]+' A'+R+','+R+' 0 '+lg+',1 '+ept[0]+','+ept[1]+'" fill="none" stroke="'+gc+'" stroke-width="8" stroke-linecap="round"/>';
  h+='<text x="50" y="55" text-anchor="middle" font-size="20" font-weight="800" fill="'+gc+'">'+score+'</text>';
  h+='<text x="50" y="68" text-anchor="middle" font-size="8" fill="var(--dim)">/'+maxS+'</text></svg>';
  h+='<div><div style="font-size:16px;font-weight:800;color:'+gc+'">'+esc(v.verdict||'')+'</div>';
  h+='<div style="font-size:16px;font-weight:800;color:var(--text)">'+esc(v.confidence||'')+'</div>';
  h+='<div style="font-size:12px;margin-top:4px"><span style="color:var(--critical)">'+tp.length+' TP</span> &nbsp; <span style="color:var(--low)">'+fp.length+' Mitigating</span> &nbsp; <span style="color:var(--info)">'+obs.length+' Observations</span></div>';
  h+='</div></div>';
  h+='<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;font-size:11px">';
  h+='<span class="badge b-low" style="opacity:.7">0\u20133 Benign</span>';
  h+='<span class="badge b-low" style="opacity:.9">4\u20137 Likely FP</span>';
  h+='<span class="badge b-medium">8\u201311 Undetermined</span>';
  h+='<span class="badge b-high">12\u201315 Suspicious</span>';
  h+='<span class="badge b-critical">16\u201320 Malicious</span>';
  h+='</div>';

  // Evidence
  if(tp.length>0){
    h+='<div class="chart-title">True Positive Evidence</div><ul class="ev-list">';
    tp.forEach(function(e){h+='<li class="ev-item ev-tp"><span class="ev-icon">&#8853;</span><span>'+esc(e)+'</span></li>';});
    h+='</ul>';
  }
  if(fp.length>0){
    h+='<div class="chart-title" style="margin-top:14px">Mitigating Factors</div><ul class="ev-list">';
    fp.forEach(function(e){h+='<li class="ev-item ev-fp"><span class="ev-icon">&#8854;</span><span>'+esc(e)+'</span></li>';});
    h+='</ul>';
  }
  if(obs.length>0){
    h+='<div class="chart-title" style="margin-top:14px">Observations</div><ul class="ev-list">';
    obs.forEach(function(e){h+='<li class="ev-item ev-obs"><span class="ev-icon">&#8505;</span><span>'+esc(e)+'</span></li>';});
    h+='</ul>';
  }
  // Recommendations
  if(recs.length>0){
    h+='<div class="chart-title" style="margin-top:16px">Recommendations</div><ul class="rec-list">';
    recs.forEach(function(r,i){
      h+='<li class="rec-item"><span class="rec-num'+(i<2&&score>=4?' urgent':'')+'">'+( i+1)+'</span><span>'+esc(r)+'</span></li>';
    });
    h+='</ul>';
  }
  return h;
}

function filterByClass(input,sel){
  var q=input.value.toLowerCase();
  document.querySelectorAll(sel).forEach(function(el){el.style.display=el.textContent.toLowerCase().indexOf(q)>=0?'':'none';});
}

// ═══════════════════════════════════════════════════════════════
// MAIN RENDER
// ═══════════════════════════════════════════════════════════════
function renderAll(){
  var meta=DATA.meta||{};
  document.getElementById('brand-sub').textContent='SOC Analysis Report \u2014 '+(meta.generated_at||'');

  renderVerdictHero();
  renderBentoGrid();
  renderChartsRow();
  renderMitreHeatmap();

  // Sections — numbered like generate_html
  var m=DATA.metrics||{};
  var sections=[
    {id:'ident',     title:'1. Process Identification & Execution Context', badge:null, fn:renderIdentification, col:false},
    {id:'timeline',  title:'2. Event Timeline', badge:null, fn:renderTimeline, col:false},
    {id:'indicators',title:'3. Behavioral Indicators', badge:(m.indicators||0)+' indicators \u00B7 '+(m.critical||0)+' critical', fn:renderIndicators, col:false},
    {id:'mitre',     title:'4. MITRE ATT\u0026CK Mapping', badge:((DATA.mitre_attack||{}).techniques||[]).length+' technique(s)', fn:renderMitre, col:false},
    {id:'chains',    title:'5. Attack Chains', badge:(DATA.attack_chains||[]).length+' chain(s)', fn:renderAttackChains, col:true},
    {id:'scripts',   title:'6. Script Content Analysis', badge:((DATA.scripts||{}).findings||[]).length+' finding(s)', fn:renderScripts, col:false},
    {id:'modules',   title:'7. Loaded Modules (DLLs)', badge:((DATA.modules||{}).suspicious||[]).length+' suspicious', fn:renderModules, col:true},
    {id:'network',   title:'8. Network Analysis', badge:(m.ext_connections||0)+' ext \u00B7 '+(m.unknown_connections||0)+' unknown', fn:renderNetwork, col:false},
    {id:'ptree',     title:'9. Process Tree', badge:null, fn:renderProcessTree, col:false},
    {id:'files',     title:'10. File Activity', badge:(m.suspicious_files||0)+' suspicious', fn:renderFiles, col:true},
    {id:'registry',  title:'11. Registry Activity', badge:(m.persistence_keys||0)+' persistence', fn:renderRegistry, col:true},
    {id:'vt',        title:'12. VirusTotal Analysis', badge:(DATA.virustotal||[]).length+' lookup(s)', fn:renderVirusTotal, col:false},
    {id:'ti',        title:'13. Threat Intelligence (MB/OTX/Shodan)', badge:((DATA.threat_intelligence||{}).malwarebazaar||[]).length+((DATA.threat_intelligence||{}).otx_hashes||[]).length+((DATA.threat_intelligence||{}).otx_ips||[]).length+((DATA.threat_intelligence||{}).otx_domains||[]).length+((DATA.threat_intelligence||{}).shodan||[]).length+' hit(s)', fn:renderThreatIntelligence, col:false},
    {id:'sigma',     title:'14. Sigma Rule Matches', badge:(m.sigma_matches||0)+' match(es)', fn:renderSigma, col:true},
    {id:'pgraph',    title:'15. Process Graph Analysis (NetworkX)', badge:(m.graph_anomalies||0)+' anomaly/anomalies', fn:renderProcessGraph, col:true},
    {id:'stats',     title:'16. Statistical Anomaly Detection', badge:(m.stat_outliers||0)+' outlier(s)', fn:renderStatistical, col:true},
    {id:'yara',      title:'17. YARA Rule Matches', badge:(m.yara_matches||0)+' match(es)', fn:renderYara, col:true},
    {id:'atkenrich', title:'18. ATT\u0026CK Enrichment (MITRE)', badge:null, fn:renderAttackEnrichment, col:true},
    {id:'ioc',       title:'19. IOC Extraction (iocextract)', badge:null, fn:renderIOC, col:true},
    {id:'lsass',     title:'20. LSASS Access', badge:(DATA.lsass||[]).length+' hit(s)', fn:renderLsass, col:true},
    {id:'cmdline',   title:'21. Command Line Analysis', badge:null, fn:renderCmdline, col:true},
    {id:'temporal',  title:'22. Temporal Sequences', badge:null, fn:renderTemporal, col:true},
    {id:'tasks',     title:'23. Scheduled Tasks', badge:(DATA.tasks||[]).length+' task(s)', fn:renderTasks, col:true},
    {id:'diagnosis', title:'Diagnosis & Verdict', badge:null, fn:renderDiagnosis, col:false},
  ];

  var html='';
  sections.forEach(function(s){
    try{
      var body=s.fn();
      html+=makeSection(s.id,s.title,s.badge,body,s.col);
    }catch(e){
      html+=makeSection(s.id,s.title,'ERROR','<div class="alert-box danger">Error: '+esc(e.message)+'</div>',false);
      console.error('Section '+s.id+':',e);
    }
  });
  document.getElementById('sections').innerHTML=html;

  // Footer
  var fw=meta.frameworks||{};
  var fwList=Object.entries(fw).filter(function(e){return e[1];}).map(function(e){return e[0];}).join(', ');
  document.getElementById('footer').innerHTML='SentinelOne DV Analyzer v'+esc(meta.analyzer_version||meta.version||'3.0')+' &nbsp;&#183;&nbsp; Behavioral analysis &nbsp;&#183;&nbsp; '+esc(meta.generated_at||'')+
    (fwList?' &nbsp;&#183;&nbsp; Frameworks: '+esc(fwList):'')+
    '<br><span style="opacity:.5">Keyboard: T = toggle theme &nbsp;&#183;&nbsp; &#9112; = print</span>';

  setTimeout(function(){animateCounters();animateBars();drawGauge();},100);
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',renderAll);
else renderAll();

// ── TOOLTIP ──
(function(){
  var box=document.createElement('div');box.className='tip-box';document.body.appendChild(box);
  var cur=null;
  document.addEventListener('mouseover',function(e){
    var el=e.target.closest('[data-tip]');
    if(!el){if(cur){box.style.opacity=0;cur=null;}return;}
    if(el===cur)return;
    cur=el;box.textContent=el.dataset.tip;box.style.opacity=1;
  });
  document.addEventListener('mousemove',function(e){
    if(!cur)return;
    var x=e.clientX+14,y=e.clientY+14;
    if(x+270>window.innerWidth)x=e.clientX-270;
    if(y+50>window.innerHeight)y=e.clientY-50;
    box.style.left=x+'px';box.style.top=y+'px';
  });
  document.addEventListener('mouseout',function(e){
    if(cur&&!cur.contains(e.relatedTarget)){box.style.opacity=0;cur=null;}
  });
})();
</script>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(
        description="Generate an HTML dashboard from s1_analyzer JSON report"
    )
    parser.add_argument("json_file", help="Path to report.json")
    parser.add_argument("-o", "--output", default=None,
                        help="Output HTML file (default: same dir as JSON, report.html)")
    args = parser.parse_args()

    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"[!] File not found: {json_path}", file=sys.stderr)
        sys.exit(1)

    data = json.loads(json_path.read_text(encoding="utf-8"))
    html = generate_html(data)

    if args.output:
        out_path = Path(args.output)
    else:
        out_path = json_path.parent / "report.html"

    out_path.write_text(html, encoding="utf-8")
    print(f"[+] Report written to {out_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
