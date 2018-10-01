from scapy.all import *
dict = {}
dict2 = {}
setl = list()
list_local = []
list_global = []
dict_local = {}
index = 0

def payload_parser(p):
    total = 0
    dict_tag = {}
    i = 0
    j = 2
    while total < len(p):
        tag = p[i:j]
        i += 2
        j += 2
        tag_length = int(p[i:j], 16)*2
        #i tag vendor specific possono essere ripetuti piu volte, dobbiamo inserirli in una lista
        if tag == 'DD':
            #attacco il vendor specific oui tag
            tag = tag + p[j + 6:j + 8]
        dict_tag[tag] = p[j:j + tag_length]
        total += tag_length + 4
        i = total
        j = i+2
    return dict_tag

class pack:
    def __init__(self, source_mac, payload):
        self.source_mac = source_mac
        result = ((int(source_mac[1], 16)) & 2) == 0
        if result == True:
            self.globalMac = True
        else:
            self.globalMac = False 
        self.payload = payload
        self.IE = payload[48:len(payload)-8]#.replace("0","")#non e una buona idea, alcune volte sfasa troppo su stringhe simili
        self.parsed_tags = payload_parser(self.IE)

    def __str__(self):
        print('mac: '+ self.source_mac)
        print(self.payload)
        print(self.IE)
        print('')
        return ""

    def printTags(self):
        for element in self.parsed_tags:
            if element != 'DD':
                print element + " -> " + self.parsed_tags[element]
            else:
                for element2 in self.parsed_tags[element]:
                    print element + " -> " + element2


class similar_mac:
    def __init__(self, mac, similarity_score, payload):
        self.mac = mac
        self.similarity_score = similarity_score
        self.payload = payload
    
    def __str__(self):
        return '\t'+ self.mac + ' -> '+ str(self.similarity_score)

def checkGlobal(mac):
    result = ((int(mac[1], 16)) & 2) == 0
    if result == True:
        return True
    else:
        return False 

def compare_similarity(a, b):
    if a.source_mac == b.source_mac:
        return 0
    else:
        if len(a.payload) != len(b.payload):
            return 0
        else:
            lena = len(a.IE)
            lenb = len(b.IE)
            localSimilarity = 0
            for j in range(min(lena,lenb)):
                #implementare comparazione bit per bit
                if a.IE[j] == b.IE[j]:
                    localSimilarity += 1
                else:
                    #sottraiamo uno per incrementare la diversita tra i vari risultati
                    if localSimilarity > 1:
                        #per evitare numeri negativi
                        localSimilarity -= 1
            res = float(localSimilarity)/float(min(lena,lenb))
            #inp = raw_input("hola")
            return res

def compareIE(a, b):
    if len(a) != len(b):
        return 0
    else:
        lena = len(a)
        lenb = len(b)
        localSimilarity = 0
        if lena == 0 or lenb == 0:
            return 0
        for j in range(min(lena,lenb)):
        #implementare comparazione bit per bit
            if a[j] == b[j]:
                localSimilarity += 1
            else:
                #sottraiamo uno per incrementare la diversita tra i vari risultati
                if localSimilarity > 1:
                    #per evitare numeri negativi
                    localSimilarity -= 1
        res = float(localSimilarity)/float(min(lena,lenb))
        #inp = raw_input("hola")
        return res

def myhexdump(x):
    x=str(x)
    l=len(x)
    i = 0
    elem = []
    while i < l:
        elem.append("%02X"%ord(x[i]))
        i+=1
    return ''.join(elem)

def PacketHandler(pkt):
    global index
    hex_dump = myhexdump(pkt.payload)
    hex_dump_wo_header = hex_dump[48:len(hex_dump)-8]
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 4:
            if checkGlobal(pkt.addr2) == True:
                list_global.append(pkt.addr2)
            else:
                #i pacchetti con indirizzo destinatario diverso da broadcast vanno tolti
                if pkt.addr1 == 'ff:ff:ff:ff:ff:ff':
                    #filtriamo eventuali ssid presenti nel payload
                    SSID_length = int(hex_dump_wo_header[2:4],16)
                    if SSID_length == 0:
                        list_local.append(pkt.addr2)
                        dict_local[pkt.addr2] = hex_dump_wo_header
                    else:
                        print 'trovato locale con ssid'
                        new_hex_dump = '0000'+hex_dump_wo_header[4+(SSID_length*2):]
                        print pkt.addr2
                        print hex_dump_wo_header
                        print new_hex_dump
                        list_local.append(pkt.addr2)
                        dict_local[pkt.addr2] = new_hex_dump
            setl.append(pkt.addr2)
            dict[index] = pack(pkt.addr2,hex_dump)
            index +=1

########################

########################
sniff(iface="wlp2s0mon", prn = PacketHandler)
########################

########################
print("Terminata raccolta di %d pacchetti probe request" % (index))
setl = set(setl)
print("%d indirizzi univoci" % (len(setl)))
print("\nIndirizzi globali: %d" % len(set(list_global)))
for element in set(list_global):
    print(element)
print("\nIndirizzi locali: %d" % len(set(list_local)))
for element in set(list_local):
    print(element)
print("")
list_locali_univoci_ordinati = set(list_local)
while list_locali_univoci_ordinati:
    first = list_locali_univoci_ordinati.pop()
    IE = dict_local[first]
    dict2[first] = []
    for mac in dict_local:
        if mac != first:
            risultato = compareIE(IE, dict_local[mac])
            if risultato != 0:
                dict2[first].append(similar_mac(mac, risultato, dict_local[mac]))
                list_locali_univoci_ordinati.remove(mac)
print("stima indirizzi locali univoci: %d" % len(dict2))

for key in dict:
    print key
    print dict[key]
    dict[key].printTags()

if False:
    for key in dict2:
        if checkGlobal(key) == False:
            print key
            print '\t'+dict_local[key]
            for element in dict2[key]:
                print element
                print '\t'+element.payload




if False:
    for key1 in dict_local:
        first = list_locali_univoci_ordinati.pop()
        if dict_local[key1].source_mac == first:
            dict2[dict[key1].source_mac] = []
            for key2 in dict:
                #magari tenere due liste separate per quelli globali e quelli no
                if dict[key2].globalMac == False:
                    risultato = compare_similarity(dict[key1], dict[key2])
                    if risultato != 0 and risultato > 0.9:
                        #stringsss = dict[key2].source_mac+" -> " +str(risultato)
                        dict2[dict[key1].source_mac].append(similar_mac(dict[key2].source_mac, risultato))
                        #print("Similarita tra %s e %s" % (dict[key1].source_mac, dict[key2].source_mac))
                        #print risultato
                        #print dict[key1].IE
                        #print dict[key2].IE
    for key in dict2:
        if checkGlobal(key) == False:
            print key
            for element in dict2[key]:
                print element


