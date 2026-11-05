import sys, os; sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base import *
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
plt.rcParams.update({'font.size':8,'axes.spines.top':False,'axes.spines.right':False,'axes.grid':True,'grid.color':'#e4e4e4','grid.linewidth':0.5,'pdf.fonttype':42})
OUT=os.path.join(OUT_DIR,'fig02_mldsa_penalty_vs_rtt.pdf')
c=load(); c=c[(c.governor=='performance')&(c.fail==0)]
f=c[(c.family=='fx')&(c.loss_nom==0)&(c.mtu==1500)&(c.chain2==False)&(c.padto==0)&(c.auth=='single')&(c.level=='L3')]
rng=np.random.default_rng(12345)
def boot(v,B=2000):
    v=np.asarray(v); i=rng.integers(0,len(v),(B,len(v))); m=v[i].mean(1); return v.mean(),np.percentile(m,2.5),np.percentile(m,97.5)
fig,axs=plt.subplots(1,2,figsize=(7.16,2.7),sharey=True)
cols={'x448_mlkem768':('#0072B2','X448+ML-KEM-768'),'hqc192':('#D55E00','HQC-192')}
R=np.array([0,50,100,150.])
for ax,proto,tt in zip(axs,['tls','quic'],['TLS 1.3','QUIC']):
    ax.plot(R,R,':',color='#666',lw=0.8); ax.plot(R,2*R,':',color='#666',lw=0.8)
    ax.text(151,150,'1 RTT',fontsize=6.5,va='center',color='#444'); ax.text(151,300,'2 RTT',fontsize=6.5,va='center',color='#444')
    for kem,(col,name) in cols.items():
        res=[]
        for r in R:
            s=f[(f.proto==proto)&(f.kem==kem)&(f.rtt==r)]
            e=s.groupby(['block','sig']).app_ms.mean().unstack(); res.append(boot(e['mldsa65']-e['secp384r1']))
        res=np.array(res)
        ax.errorbar(R,res[:,0],yerr=[res[:,0]-res[:,1],res[:,2]-res[:,0]],color=col,marker='o',ms=3.5,lw=1,capsize=2,label=name)
    ax.set_xlabel('RTT (ms)'); ax.set_title(tt); ax.set_xlim(-5,175)
axs[0].set_ylabel('Penalty $D$ (ms)'); axs[0].legend(frameon=False,loc='upper left',fontsize=7)
fig.tight_layout(); fig.savefig(OUT); print('ok')
