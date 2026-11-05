import numpy as np, pandas as pd, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from base import find, OUT_DIR
OUT = OUT_DIR.rstrip('/') + '/'
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':8,'axes.labelsize':8,'axes.titlesize':8.5,
  'legend.fontsize':7,'xtick.labelsize':7.5,'ytick.labelsize':7.5,'axes.spines.top':False,'axes.spines.right':False,
  'axes.linewidth':0.7,'pdf.fonttype':42,'ps.fonttype':42,'axes.grid':True,'grid.color':'#e4e4e4','grid.linewidth':0.5})
BLUE='#0072B2'; ORG='#D55E00'; GRN='#009E73'; GREY='#555555'; PURP='#CC79A7'

# ---------------- Fig 03 ----------------
d=pd.read_csv(find('p2_c7_size_decomposition.csv'))
d=d[d.composante.isin(['total','taille','residu'])]
lab={'total':'Total penalty','taille':'Size component','residu':'Residual (computation)'}
col={'total':'#222222','taille':ORG,'residu':PURP}
fig,axs=plt.subplots(1,2,figsize=(7.16,2.9),sharey=True)
losses=[0,1,2,5]
for ax,proto,tt in zip(axs,['quic','tls'],['QUIC','TLS']):
    for ci,comp in enumerate(['total','taille','residu']):
        for mi,mtu in enumerate([1500,1280]):
            s=d[(d.proto==proto)&(d.composante==comp)&(d.mtu==mtu)].set_index('loss_nom').loc[losses]
            x=np.array(range(4))+(ci-1)*0.24+(mi-0.5)*0.09
            ax.errorbar(x,s['mean'],yerr=[s['mean']-s['lo'],s['hi']-s['mean']],fmt='o' if mtu==1500 else 's',
                ms=3.6,mfc=col[comp] if mtu==1500 else 'white',mec=col[comp],ecolor=col[comp],color=col[comp],lw=0.9,capsize=1.5)
    ax.axhline(0,color='#888',lw=0.7)
    ax.set_xticks(range(4)); ax.set_xticklabels([str(l) for l in losses])
    ax.set_xlabel('Nominal loss rate (%)'); ax.set_title(tt+(' (loss results secondary)' if proto=='tls' else ''))
axs[0].set_ylabel('Difference in handshake duration (ms)')
h=[Line2D([],[],marker='o',ls='',color=col[c],label=lab[c]) for c in col]
h+=[Line2D([],[],marker='o',ls='',mfc='#777',mec='#777',color='#777',label='MTU 1500 (filled)'),
    Line2D([],[],marker='s',ls='',mfc='white',mec='#777',color='#777',label='MTU 1280 (open)')]
fig.legend(handles=h,loc='lower center',ncol=5,frameon=False,bbox_to_anchor=(0.5,-0.02))
fig.tight_layout(rect=(0,0.09,1,1)); fig.savefig(OUT+'fig03_size_matched_control_decomposition.pdf'); plt.close(fig)

# ---------------- Fig 04 ----------------
n=pd.read_csv(find('p5_natural_lossless.csv'))
n=n[~n.in_sample].copy()
def nm(r):
    g=r.groupe; k={'x448_mlkem768':'X448+ML-KEM-768','hqc192':'HQC-192'}[r.kem]; p=r.proto.upper()
    if g.startswith('CHAINE'): return f'{p} {k}, two-level chain'
    if g.startswith('MTU'): return f'{p} {k}, MTU {g.split()[1]}'
    return f'{p} {k}, padded ECDSA, MTU {g.split("MTU ")[1].rstrip(")")}'
n['name']=n.apply(nm,axis=1)
order=[0,1,2,3,4,5,6,7,8,9,10,11]
n=n.reset_index(drop=True)
fig,(a,b)=plt.subplots(1,2,figsize=(7.16,3.3),gridspec_kw={'width_ratios':[1.35,1]})
y=np.arange(len(n))[::-1]
for yi,(_,r) in zip(y,n.iterrows()):
    c=BLUE if r.proto=='tls' else ORG
    a.errorbar(r.k_obs_median,yi,xerr=[[r.k_obs_median-r.k_obs_median_lo],[r.k_obs_median_hi-r.k_obs_median]],fmt='o',ms=3.8,color=c,lw=1,capsize=1.5)
    a.plot(r.k_pred_final,yi,'D',mfc='none',mec='k',ms=6.5,mew=0.9)
    if r.informative: a.text(1.36,yi,'*',ha='center',va='center',fontsize=11)
a.set_yticks(y); a.set_yticklabels(n.name,fontsize=6.6); a.set_xlim(-0.12,1.42)
a.set_xlabel('Extra round trips $k$ (median per block)')
a.set_title('(A) Predicted and observed $k$, held-out cells',loc='left')
a.legend(handles=[Line2D([],[],marker='o',ls='',color=BLUE,label='TLS observed'),Line2D([],[],marker='o',ls='',color=ORG,label='QUIC observed'),
   Line2D([],[],marker='D',ls='',mfc='none',mec='k',label='Predicted'),Line2D([],[],marker='*',ls='',color='k',ms=8,label='Informative (trivial rule fails)')],
   loc='center right',bbox_to_anchor=(1.0,0.52),frameon=True,framealpha=0.95,edgecolor='#ccc',fontsize=6.3)
t=pd.read_csv(find('p5_tau_profiles.csv'))
for _,r in t.iterrows():
    c=BLUE if r.proto=='tls' else ORG
    for key,mk,fill,dx in [('T_125','o',True,-0.25),('T_167','^',False,0.25)]:
        b.errorbar(r.srv_cpu_excess_ms+dx,r[key],yerr=[[r[key]-r[key+'_lo']],[r[key+'_hi']-r[key]]],fmt=mk,ms=4,color=c,
                   mfc=c if fill else 'white',lw=0.9,capsize=1.2)
b.plot([0,50],[0,50],'k--',lw=0.8); b.set_xlim(0,50); b.set_ylim(-5,50)
b.set_xlabel('Server CPU surcharge (ms)'); b.set_ylabel('Estimated overlap constant $T$ (ms)')
b.set_title('(B) $T$ versus CPU surcharge',loc='left')
b.legend(handles=[Line2D([],[],marker='o',ls='',color=BLUE,label='TLS'),Line2D([],[],marker='o',ls='',color=ORG,label='QUIC'),
   Line2D([],[],marker='o',ls='',mfc='#777',mec='#777',color='#777',label='Moderate profile'),
   Line2D([],[],marker='^',ls='',mfc='white',mec='#777',color='#777',label='Degraded profile'),
   Line2D([],[],ls='--',color='k',label='Identity')],loc='upper left',fontsize=6.3,frameon=True,framealpha=0.95,edgecolor='#ccc')
fig.tight_layout(); fig.savefig(OUT+'fig04_held_out_cells_and_overlap_constant.pdf'); plt.close(fig)

# ---------------- Fig 13 ----------------
L=pd.read_csv(find('p6_load_niveaux.csv')); L=L[L.tls_server!='stock']
g=L.groupby(['proto','sig','kem','conc','block'],as_index=False).agg(X=('X','mean'),fail=('fail','mean'),us=('util_srv','mean'))
rng=np.random.default_rng(20261104)
def boot(v,B=4000):
    v=np.asarray(v); idx=rng.integers(0,len(v),(B,len(v))); m=v[idx].mean(1)
    return v.mean(),np.percentile(m,2.5),np.percentile(m,97.5)
concs=[1,2,4,8,16,32,64]
styles={('tls','secp384r1'):(BLUE,'--','o',True),('tls','mldsa65'):(BLUE,'-','o',False),
        ('quic','secp384r1'):(ORG,'--','s',True),('quic','mldsa65'):(ORG,'-','s',False)}
kems=[('x448_mlkem768','X448+ML-KEM-768'),('hqc192','HQC-192')]
fig,axs=plt.subplots(2,3,figsize=(7.16,3.9),sharex=True)
for r,(kem,kn) in enumerate(kems):
    for (proto,sig),(c,ls,mk,hollow) in styles.items():
        res=[]
        for cc in concs:
            s=g[(g.proto==proto)&(g.sig==sig)&(g.kem==kem)&(g.conc==cc)].sort_values('block')
            res.append([boot(s.X),boot(s.us),boot(100*s.fail)])
        res=np.array(res)  # conc x 3 metrics x 3
        for j in range(3):
            ax=axs[r,j]; xs=np.array(range(7))
            ax.fill_between(xs,res[:,j,1],res[:,j,2],color=c,alpha=0.15,lw=0)
            ax.plot(xs,res[:,j,0],color=c,ls=ls,marker=mk,ms=3.2,mfc='white' if hollow else c,lw=1)
    axs[r,0].set_ylabel(f'{kn}\n'+'Handshakes per second' if False else 'Throughput $X$ (conn/s)')
    axs[r,0].set_title(f'{kn}: throughput',loc='left'); axs[r,1].set_title(f'{kn}: utilization',loc='left'); axs[r,2].set_title(f'{kn}: failures',loc='left')
    axs[r,1].set_ylim(0.3,1.03); axs[r,1].set_ylabel('Utilization $U$')
    axs[r,2].set_ylabel('Failed attempts (%)')
    axs[r,0].set_ylim(0,None)
    if r==0: axs[r,2].set_ylim(0,0.05)
for j in range(3):
    axs[1,j].set_xticks(range(7)); axs[1,j].set_xticklabels([str(c) for c in concs]); axs[1,j].set_xlabel('Concurrent clients $c$')
h=[Line2D([],[],color=BLUE,marker='o',ls='-',label='TLS (MT), ML-DSA-65'),Line2D([],[],color=BLUE,marker='o',ls='--',mfc='white',label='TLS (MT), ECDSA P-384'),
   Line2D([],[],color=ORG,marker='s',ls='-',label='QUIC, ML-DSA-65'),Line2D([],[],color=ORG,marker='s',ls='--',mfc='white',label='QUIC, ECDSA P-384')]
fig.legend(handles=h,loc='lower center',ncol=4,frameon=False,bbox_to_anchor=(0.5,-0.01))
fig.tight_layout(rect=(0,0.05,1,1)); fig.savefig(OUT+'fig13_load_throughput_and_latency.pdf'); plt.close(fig)
print('ok')
