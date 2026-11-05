import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base import *
p=load_p6()
r=p[p.arm=='captures_v3_comp'].copy(); print(r.shape)
for k in ['comp','cert_type','pad','chain','rtt','sig','kem','block','cert_comp','mode_planned']: print(k, r[k].unique()[:12])
print(r.groupby(['comp','cert_type','pad','chain']).size().head(40))
rng=np.random.default_rng(20261027)
def boot(v,B=4000):
    v=np.asarray(v); i=rng.integers(0,len(v),(B,len(v))); m=v[i].mean(1); return v.mean(),np.percentile(m,2.5),np.percentile(m,97.5)
x=r[(r.kem=='x448_mlkem768')&(r.rtt==50)&(r.proto=='tls')]
rows=[]
for (sig,pad,chain),g in x.groupby(['sig','pad','chain']):
    for comp in ['zlib','brotli','zstd']:
        for tag,gg in [('all',g),('no_b5',g[g.block!=5])]:
            e=gg.groupby(['block','comp']).app_ms.mean().unstack()
            if comp not in e or 'none' not in e: continue
            d=(e[comp]-e['none']).dropna(); m,lo,hi=boot(d)
            rows.append((sig,pad,chain,comp,tag,round(m,2),f'[{lo:.2f},{hi:.2f}]',len(d)))
o=pd.DataFrame(rows,columns=['sig','pad','chain','comp','subset','delta_ms','ci','nb']); 
pv=o.pivot_table(index=['sig','pad','chain','comp'],columns='subset',values='delta_ms'); pd.set_option('display.width',200); print(pv)
print(x.block.value_counts().sort_index().to_dict())
