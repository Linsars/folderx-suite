import sys
def balance(path):
    s=open(path).read();i=0;n=len(s);b=0;pp=0;ins=inc=inl=ch=False
    line=1
    while i<n:
        c=s[i]
        if c=='\n':line+=1
        if inl:
            if c=='\n':inl=False
            i+=1;continue
        if inc:
            if c=='*' and i+1<n and s[i+1]=='/':inc=False;i+=2;continue
            i+=1;continue
        if ins:
            if c=='\\':i+=2;continue
            if c=='"':ins=False
            i+=1;continue
        if ch:
            if c=='\\':i+=2;continue
            if c=="'":ch=False
            i+=1;continue
        if c=='/' and i+1<n and s[i+1]=='/':inl=True;i+=2;continue
        if c=='/' and i+1<n and s[i+1]=='*':inc=True;i+=2;continue
        if c=='"':ins=True;i+=1;continue
        if c=="'":ch=True;i+=1;continue
        if c=='{':b+=1
        elif c=='}':b-=1
        elif c=='(':pp+=1
        elif c==')':pp-=1
        i+=1
    print('%-24s {}=%d ()=%d'%(path.split('/')[-1],b,pp))
for p in sys.argv[1:]: balance(p)
