import numpy as np, pandas as pd, matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':8,'axes.titlesize':8,'legend.fontsize':6.6,
  'xtick.labelsize':7,'ytick.labelsize':7.5,'axes.spines.top':False,'axes.spines.right':False,'axes.linewidth':0.7,
  'pdf.fonttype':42,'axes.grid':True,'grid.color':'#e4e4e4','grid.linewidth':0.5})
c=pd.read_csv('analysis_S/S_cells.csv'); b=pd.read_csv('analysis_S/S_brackets.csv')
BLUE='#0072B2'; ORG='#D55E00'
fams=[('TLS_1500','TLS, MTU 1500','pred_octets','pred_bio','byte rule','write-buffer rule'),
      ('TLS_1280','TLS, MTU 1280','pred_octets','pred_bio','byte rule','write-buffer rule'),
      ('QUIC_A','QUIC, X448+ML-KEM-768','pred_amp','pred_cwnd','anti-amplification','window only'),
      ('QUIC_B','QUIC, X25519+ML-KEM-512','pred_amp','pred_cwnd','anti-amplification','window only')]
fig,axs=plt.subplots(1,4,figsize=(7.16,2.25),sharey=True)
xs=np.logspace(np.log10(2300),np.log10(52000),400)
for ax,(f,t,ca,cb,la,lb) in zip(axs,fams):
    bb=b[b.family==f].sort_values('step'); d=c[c.family==f]
    th={k:[float(bb[bb.step==s][col].iloc[0]) for s in (1,2)] for k,col in (('a',ca),('b',cb))}
    for k,col,ls in (('a',ORG,'--'),('b',BLUE,'-')):
        s1,s2=th[k]; ax.step(xs,(xs>=s1).astype(int)+(xs>=s2).astype(int),where='post',color=col,ls=ls,lw=1.4,alpha=.9)
    ax.axvspan(min(th['a'][0],th['b'][0]),max(th['a'][0],th['b'][0]),color='#ddd',alpha=.6,lw=0,zorder=0)
    ax.errorbar(d.chain_target,d.khat,yerr=[d.khat-d.ci_lo,d.ci_hi-d.khat],fmt='o',ms=3,color='k',lw=.8,capsize=1.2,zorder=3)
    ax.set_xscale('log'); ax.set_xlim(2300,52000); ax.set_ylim(-.25,2.35); ax.minorticks_off()
    ax.set_xticks([3000,10000,30000]); ax.set_xticklabels(['3','10','30']); ax.set_yticks([0,1,2])
    ax.set_title(t,fontsize=7.6); ax.set_xlabel('Chain size (kB)')
    ax.legend(handles=[Line2D([],[],color=ORG,ls='--',lw=1.4,label=la),Line2D([],[],color=BLUE,lw=1.4,label=lb)],loc='upper left',frameon=False,handlelength=1.6,borderpad=.1,labelspacing=.2)
axs[0].set_ylabel('Extra round trips $k$')
fig.tight_layout(pad=.4,w_pad=.5); fig.savefig('paper_figs/fig14_preregistered_staircase.pdf'); print('ok')
