p = "seuil_S3/predict_freeze_S3.py"
t = open(p, encoding="utf-8").read()
if "--pcap-sizes" in t:
    raise SystemExit("deja patche : rien a faire")
old1 = '''    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    fam, f = a.family, dict(S2_FAMILIES[a.family])'''
new1 = '''    ap.add_argument("--pcap-sizes", default=None, help="tailles des cellules pcap imposees (liste separee par des virgules) : donne au temoin les memes cellules pcap que le traitement")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    fam, f = a.family, dict(S2_FAMILIES[a.family])'''
assert t.count(old1) == 1
t = t.replace(old1, new1)
old2 = '''    f["pcap"] = sorted(set(pcap))[:8]'''
new2 = '''    f["pcap"] = sorted(set(pcap))[:8]
    if a.pcap_sizes:
        f["pcap"] = sorted(int(x) for x in a.pcap_sizes.split(","))
        assert set(f["pcap"]) <= set(f["sizes"]), "pcap-sizes doit etre inclus dans sizes"'''
assert t.count(old2) == 1
t = t.replace(old2, new2)
open(p, "w", encoding="utf-8").write(t)
print("predict_freeze_S3.py patche (--pcap-sizes)")
