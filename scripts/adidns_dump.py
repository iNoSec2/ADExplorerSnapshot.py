# Script to dump ADIDNS records
# note: Supports legacy DNS zones only. Naming contexts for (Domain|Forest)DnsZones are not being saved in the snapshot
# author: dust-life

from adexpsnapshot import ADExplorerSnapshot
from bloodhound.ad.utils import ADUtils
from adidnsdump import dnsdump

import sys
fh = open(sys.argv[1],"rb")

ades = ADExplorerSnapshot(fh, '.')
ades.preprocessCached()

findDN = [
    f',CN=MicrosoftDNS,CN=System,{ades.domain_dn}'.lower(),
    f',CN=MicrosoftDNS,DC=ForestDnsZones,{ades.forest_dn}'.lower(),
    f',CN=MicrosoftDNS,DC=DomainDnsZones,{ades.domain_dn}'.lower(),
]

for k,v in ades.dncache.items():
    for dn in findDN:
        if k.lower().endswith(dn.lower()):
            entry = ades.snap.getObject(v)
            for address in ADUtils.get_entry_property(entry, 'dnsRecord', [], raw=True):
                dr = dnsdump.DNS_RECORD(address)
                if dr['Type'] == 1:
                    address = dnsdump.DNS_RPC_RECORD_A(dr['Data'])
                    print("[+]","Type:",dnsdump.RECORD_TYPE_MAPPING[dr['Type']],"name:",k.split(',')[0].split('=')[1],"value:",address.formatCanonical())
                if dr['Type'] in [a for a in dnsdump.RECORD_TYPE_MAPPING if dnsdump.RECORD_TYPE_MAPPING[a] in ['CNAME', 'NS', 'PTR']]:
                    address = dnsdump.DNS_RPC_RECORD_NODE_NAME(dr['Data'])
                    print("[+]","Type:",dnsdump.RECORD_TYPE_MAPPING[dr['Type']],"name:",k.split(',')[0].split('=')[1],"value:",address[list(address.fields)[0]].toFqdn())
                elif dr['Type'] == 28:
                    address = dnsdump.DNS_RPC_RECORD_AAAA(dr['Data'])
                    print("[+]","Type:",dnsdump.RECORD_TYPE_MAPPING[dr['Type']],"name:",k.split(',')[0].split('=')[1],"value:",address.formatCanonical())
                elif dr['Type'] not in [a for a in dnsdump.RECORD_TYPE_MAPPING if dnsdump.RECORD_TYPE_MAPPING[a] in ['A', 'AAAA,' 'CNAME', 'NS']]:
                    print("[+]","name:",k.split(',')[0].split('=')[1],'Unexpected record type seen: {}'.format(dr['Type']))
