#!/usr/bin/env python3
# 从 MFWebBridgeForge.m 提取 mfWFBuiltinJS 的 ObjC 字符串字面量, 正确反转义 → 纯 JS, 交 node 校验
import re, sys, subprocess
src=open('/var/minis/workspace/iaphunter-tweak/MFWebBridgeForge.m',encoding='utf-8').read()

# 定位函数体: 从 "mfWFBuiltinJS(void)" 后第一个 return 到该 return 语句结束(以行首 '}' 收尾)
i=src.index('mfWFBuiltinJS(void)')
ret=src.index('return',i)
# 收集从 ret 开始的所有 @"..." (ObjC adjacent string literals), 直到遇到 ';' (在字符串外)
j=ret+len('return')
parts=[]
n=len(src)
while j<n:
    # skip whitespace
    while j<n and src[j] in ' \t\r\n': j+=1
    if j<n and src[j]==';': break
    if src[j:j+2]=='@"':
        j+=2
        buf=[]
        while j<n:
            c=src[j]
            if c=='\\':   # ObjC escape: 保留反斜杠+下一字符原样(交给下面统一处理)
                buf.append(src[j]); buf.append(src[j+1]); j+=2; continue
            if c=='"':
                j+=1; break
            buf.append(c); j+=1
        parts.append(''.join(buf))
    else:
        j+=1

raw=''.join(parts)
# 现在 raw 是 ObjC 字面量内容(含 ObjC 转义). 反转义: \" -> " , \\ -> \  (其余 \x 保留)
out=[]; k=0
while k<len(raw):
    if raw[k]=='\\' and k+1<len(raw):
        nx=raw[k+1]
        if nx=='"': out.append('"'); k+=2; continue
        if nx=='\\': out.append('\\'); k+=2; continue
        out.append('\\'); out.append(nx); k+=2; continue
    out.append(raw[k]); k+=1
js=''.join(out)
open('/tmp/wf_builtin.js','w',encoding='utf-8').write(js)
print("JS 长度:",len(js))
r=subprocess.run(['node','-c','/tmp/wf_builtin.js'],capture_output=True,text=True)
if r.returncode==0: print("✅ 内置引擎 JS 语法 OK")
else: print("✗ 语法错:\n",r.stderr[:600]); print("--- JS 全文 ---\n",js)
