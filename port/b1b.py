import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base import *
p=load_p6()
r=p[p.arm=='captures_v3_resume'].copy()
print(r.shape, r.groupby('proto').size().to_dict(), r.app_ms.isna().sum())
print(pd.crosstab(r.mode_planned,r.resumed))
print(r.groupby(['proto','mode_planned']).resumed.mean().round(4))
print(sorted(r.loss.unique()), sorted(r.rtt.unique()), r.block.nunique())
rng=np.random.default_rng(20261027)
def boot(v,B=4000):
    v=np.asarray(v); i=rng.integers(0,len(v),(B,len(v))); m=v[i].mean(1); return v.mean(),np.percentile(m,2.5),np.percentile(m,97.5)
def slopes(d,modecol,modeval,how='mean',proto='quic',kem='x448_mlkem768'):
    s=d[(d.proto==proto)&(d.kem==kem)&(d.loss==0)&(d[modecol]==modeval)&(d.rtt.isin([0,50,100,150]))]
    e=s.groupby(['block','rtt','sig']).app_ms.agg(how).unstack()
    D=(e['mldsa65']-e['secp384r1']).unstack()
    x=np.array([0,50,100,150.]);xm=x-x.mean()
    return (D[[0.,50.,100.,150.]].values*xm).sum(1)/(xm**2).sum(), D
out=[]
for tag,dd in [('all',r),('no_b7',r[r.block!=7]),('no_b7_hs',None)]:
    if dd is None: continue
    for proto in ['quic','tls']:
      for modecol,mv,lab in [('mode_planned','full','full (planned)'),('mode_planned','resumed','resumed (ITT, as scheduled)'),('resumed',1,'resumed (actually resumed, per-protocol)')]:
        for how in ['mean','median']:
            try:
                s,D=slopes(dd,modecol,mv,how,proto); m,lo,hi=boot(s)
                out.append((tag,proto,lab,how,f'{m:.3f} [{lo:.3f},{hi:.3f}]',len(s)))
            except Exception as ex: out.append((tag,proto,lab,how,str(ex)[:30],0))
o=pd.DataFrame(out,columns=['subset','proto','arm','est','slope','nblocks']); pd.set_option('display.width',200,'display.max_colwidth',60); print(o.to_string())
