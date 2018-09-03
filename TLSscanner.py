#!/usr/bin/python3
import sys
from scapy.all import get_if_list, sniff, IP, TCP
from scapy.layers.tls.all import *
from scapy.layers.tls.basefields import _tls_version
from scapy.layers.tls.crypto.suites import _tls_cipher_suites
from scapy.layers.tls.keyexchange import _tls_hash_sig

def main():
    port = 443
    with PcapReader(sys.argv[1]) as pcap_reader:
    
    #with PcapReader(tcpdump(sys.argv[1], args=["-w", "-", "tcp and port %d" % port], getfd=True)) as pcap_reader:
        check_pkts(pcap_reader)


RSA_MODULI_KNOWN_FACTORED = (1522605027922533360535618378132637429718068114961380688657908494580122963258952897654000350692006139,  # RSA-100
                                 # RSA-110
                                 35794234179725868774991807832568455403003778024228226193532908190484670252364677411513516111204504060317568667,
                                 # RSA-120
                                 227010481295437363334259960947493668895875336466084780038173258247009162675779735389791151574049166747880487470296548479,
                                 # RSA-129
                                 114381625757888867669235779976146612010218296721242362562561842935706935245733897830597123563958705058989075147599290026879543541,
                                 # RSA-130
                                 1807082088687404805951656164405905566278102516769401349170127021450056662540244048387341127590812303371781887966563182013214880557,
                                 # RSA-140
                                 21290246318258757547497882016271517497806703963277216278233383215381949984056495911366573853021918316783107387995317230889569230873441936471,
                                 # RSA-150
                                 155089812478348440509606754370011861770654545830995430655466945774312632703463465954363335027577729025391453996787414027003501631772186840890795964683,
                                 # RSA-155
                                 10941738641570527421809707322040357612003732945449205990913842131476349984288934784717997257891267332497625752899781833797076537244027146743531593354333897,
                                 # RSA-160
                                 2152741102718889701896015201312825429257773588845675980170497676778133145218859135673011059773491059602497907111585214302079314665202840140619946994927570407753,
                                 # RSA-170
                                 26062623684139844921529879266674432197085925380486406416164785191859999628542069361450283931914514618683512198164805919882053057222974116478065095809832377336510711545759,
                                 # RSA-576
                                 188198812920607963838697239461650439807163563379417382700763356422988859715234665485319060606504743045317388011303396716199692321205734031879550656996221305168759307650257059,
                                 # RSA-180
                                 191147927718986609689229466631454649812986246276667354864188503638807260703436799058776201365135161278134258296128109200046702912984568752800330221777752773957404540495707851421041,
                                 # RSA-190
                                 1907556405060696491061450432646028861081179759533184460647975622318915025587184175754054976155121593293492260464152630093238509246603207417124726121580858185985938946945490481721756401423481,
                                 # RSA-640
                                 3107418240490043721350750035888567930037346022842727545720161948823206440518081504556346829671723286782437916272838033415471073108501919548529007337724822783525742386454014691736602477652346609,
                                 # RSA-200
                                 27997833911221327870829467638722601621070446786955428537560009929326128400107609345671052955360856061822351910951365788637105954482006576775098580557613579098734950144178863178946295187237869221823983,
                                 # RSA-210
                                 245246644900278211976517663573088018467026787678332759743414451715061600830038587216952208399332071549103626827191679864079776723243005600592035631246561218465817904100131859299619933817012149335034875870551067,
                                 # R SA-704
                                 74037563479561712828046796097429573142593188889231289084936232638972765034028266276891996419625117843995894330502127585370118968098286733173273108930900552505116877063299072396380786710086096962537934650563796359,
                                 # RSA-768
                                 1230186684530117755130494958384962720772853569595334792197322452151726400507263657518745202199786469389956474942774063845925192557326303453731548268507917026122142913461670429214311602221240479274737794080665351419597459856902143413,
                            )

def check_pkts(pkts):
    points = []
    events = []
    for pkt in pkts:
        #if pkt.haslayer(TLS):
        #    if pkt[TLS].len-3 > len(bytes(pkt[TLS].msg)):
        #        print("aha" + str(len(bytes(pkt[TLS].msg))))
        #        pkt.show()
        #        break
        
        #pkt.show()

        if pkt.haslayer(SSLv2ClientHello):
            sid = (pkt[IP].src, pkt[IP].dst, 'SSLv2')

            desc = '{}{}{}'.format(*sid)
            if desc in points:
                continue
            points.append(desc)

            print("{} -> {}\n\t{}".format(*sid))
            events.append((*sid, "PROTOCOL VERSION - SSLv2 supported ", pkt[SSLv2ClientHello].version))

        if pkt.haslayer(TLSClientHello):

            sni = ""
            if pkt.haslayer(TLS_Ext_ServerName):
                for name in pkt[TLS_Ext_ServerName].servernames:
                    sni += name.servername.decode("ascii")

            sid = (pkt[IP].src, pkt[IP].dst, sni)

            desc = '{}{}{}'.format(*sid)
            if desc in points:
                continue
            points.append(desc)

            print("{} -> {} ({})".format(*sid))
            chello = pkt[TLSClientHello]
            #print(chello.random_bytes)
            #for cip in chello.ciphers:
            #    print(_tls_cipher_suites[cip])
            
            try:
                if "SSLv3" == _tls_version[chello.version]:
                    events.append((*sid, "PROTOCOL VERSION - SSLv3 supported ", pkt[SSLv2ClientHello].version))
            except KeyError:
                pass

            tmp = chello.comp.copy()
            if 0 in tmp:
                tmp.remove(0)
            if len(tmp):
                events.append((*sid, "CRIME - supports compression", chello.comp))

            #--------------------------------------check Ciphers--------------------------------
            cipher_namelist = []
            if chello.ciphers:
                for c in chello.ciphers:
                    try:
                        cipher_namelist.append(_tls_cipher_suites[c])
                    except KeyError:
                        pass

            tmp = [
                c for c in cipher_namelist if isinstance(
                    c,
                    str) and "SSLV2" in c.upper() and "EXP" in c.upper()]
            if tmp:
                events.append((*sid, "DROWN - SSLv2 with EXPORT ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, str) and "EXP" in c.upper()]
            if tmp:
                events.append((*sid, "CIPHERS - Export ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, str) and "RC4" in c.upper()]
            if tmp:
                events.append((*sid, "CIPHERS - RC4 ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, str) and "MD2" in c.upper()]
            if tmp:
                events.append((*sid, "CIPHERS - MD2 ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, str) and "MD4" in c.upper()]
            if tmp:
                events.append((*sid, "CIPHERS - MD4 ciphers enabled", tmp))
            tmp = [c for c in cipher_namelist if isinstance(c, str) and "MD5" in c.upper()]
            if tmp:
                events.append((*sid, "CIPHERS - MD5 ciphers enabled", tmp))

            tmp = [c for c in cipher_namelist if isinstance(c, str) and "RSA_EXP" in c.upper()]
            if tmp:
                # only check DHE EXPORT for now. we might want to add DH1024 here.
                events.append((*sid, "FREAK - server supports RSA_EXPORT cipher suites", tmp))
            tmp = [
                c for c in cipher_namelist if isinstance(
                    c,
                    str) and "DHE_" in c.upper() and "EXPORT_" in c.upper()]
            if tmp:
                # only check DHE EXPORT for now. we might want to add DH1024 here.
                events.append((*sid, "LOGJAM - server supports weak DH-Group (512) (DHE_*_EXPORT) cipher suites", tmp))

            if pkt.haslayer(TLS_Ext_SignatureAlgorithms):
                for alg in pkt[TLS_Ext_SignatureAlgorithms].sig_algs:
                    if _tls_hash_sig[alg] in ("md5+rsa","sha1+rsa","md5+ecdsa","sha256+ecdsa","md5+dsa","sha1+dsa"):
                        events.append(
                            (*sid, "SLOTH - announces capability of signature/hash algorithm: %s" %
                                (_tls_hash_sig[alg]), _tls_hash_sig[alg]))

        if pkt.haslayer(TLSServerHello):
            print("%s <- %s [ServerHello]" % (pkt[IP].dst, pkt[IP].src))
            shello = pkt[TLSServerHello]
            try:
                print(_tls_version[shello.version])
                #print(shello.random_bytes)
                print(_tls_cipher_suites[shello.cipher])
            except KeyError:
                pass


    for event in events:
        print("{} -> {}: {} ({})".format(*event))

if __name__ == "__main__":
    main()
