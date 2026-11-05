import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base import *
c=load(); c=c[(c.governor=='performance')&(c.fail==0)]
if 'kernel' in c: print('kernel by block:', c.groupby('block').kernel.agg(lambda s:sorted(set(s))).loc[[19,20]].to_dict())
base=c[(c.family=='fx')&(c.loss_nom==0)&(c.mtu==1500)&(c.chain2==False)&(c.padto==0)&(c.auth=='single')&(c.level=='L3')]
base=base[base.kem.isin(['x448_mlkem768','hqc192'])&base.sig.isin(['mldsa65','secp384r1'])]
rng=np.random.default_rng(12345)
def blockD(f,proto,kem,how):
    r={}
    for rtt in [0,50,100,150]:
        s=f[(f.proto==proto)&(f.kem==kem)&(f.rtt==rtt)]
        e=s.groupby(['block','sig']).app_ms.agg(how).unstack(); r[rtt]=e['mldsa65']-e['secp384r1']
    return pd.DataFrame(r)
def slope3(D):
    x=np.array([50,100,150.]); xm=x-x.mean(); return (D[[50,100,150]].values*xm).sum(1)/(xm**2).sum()
def boot(v,B=2000):
    v=np.asarray(v); i=rng.integers(0,len(v),(B,len(v))); m=v[i].mean(1); return v.mean(),np.percentile(m,2.5),np.percentile(m,97.5)
rows=[]
for proto in ['tls','quic']:
  for kem in ['x448_mlkem768','hqc192']:
    r={'proto':proto,'kem':kem}
    for tag,f in [('all',base),('no_b20',base[base.block!=20])]:
      for how in ['mean','median']:
        D=blockD(f,proto,kem,how); m,lo,hi=boot(slope3(D)); r[f'{tag}_{how}']=f'{m:.3f} [{lo:.3f},{hi:.3f}]'
        if tag=='all':
            for rtt in [50,100,150]:
                m2=boot(D[rtt]); r[f'D{rtt}_{how}']=round(m2[0],1)
    rows.append(r)
out=pd.DataFrame(rows); pd.set_option('display.width',250,'display.max_columns',30); print(out.T)
out.to_csv('sens_slopes.csv',index=False)
