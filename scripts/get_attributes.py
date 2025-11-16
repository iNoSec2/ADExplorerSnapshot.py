# Script to dump specific AD attributes
# author: @knavesec

from adexpsnapshot import ADExplorerSnapshot
from rich.progress import track
from bloodhound.ad.utils import ADUtils
from datetime import datetime, timezone, timedelta
from pathlib import Path
import argparse
import os

def convert_ad_timestamp(timestamp):
    if timestamp is None:
        return None
    base_date = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return base_date + timedelta(microseconds=timestamp / 10)

parser = argparse.ArgumentParser(add_help=True, description="Script to dump interesting stuff from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-a", "--attributes", required=True, action="append", nargs="*", help="Attributes to extract")
parser.add_argument("-t", "--type", required=False, default=None, help="Object type (User, Computer, Group, Base), optional and case-sensitive")
args = parser.parse_args()

ades = ADExplorerSnapshot(args.snapshot, ".")
ades.preprocessCached()

# Get snapshot time
snapshot_time = datetime.fromtimestamp(ades.snap.header.filetimeUnix, tz=timezone.utc)

# ty stack overflow for reducing a 2d array
attrs = [j for sub in args.attributes for j in sub]

out_list = []
out_list.append("||".join(attrs))

for idx, obj in track(enumerate(ades.snap.objects), description="Processing objects", total=ades.snap.header.numObjects):
    # get computers
    object_resolved = ADUtils.resolve_ad_entry(obj)
    if object_resolved['type'] == args.type or args.type == None:
        obj_out = []
        for attr in attrs:
            if attr in ['lastlogontimestamp', 'whencreated', 'pwdlastset']:
                obj_out.append(str(convert_ad_timestamp(ADUtils.get_entry_property(obj, attr))))
            else:
                val = ADUtils.get_entry_property(obj, attr)
                obj_out.append(str(val) if val is not None else "")
        if obj_out:
            out_list.append("||".join(obj_out))

outFile = open(Path("objs.txt"), "w")
outFile.write(os.linesep.join(out_list))
