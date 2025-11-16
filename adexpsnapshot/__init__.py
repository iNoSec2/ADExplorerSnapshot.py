import logging
from rich.logging import RichHandler
from rich.console import Console
from rich.progress import track

import argparse
import os, pathlib
from pickle import Pickler, Unpickler

from bloodhound.ad.utils import ADUtils

from collections import defaultdict
from requests.structures import CaseInsensitiveDict

import datetime
from enum import Enum

class ADExplorerSnapshot(object):
    OutputMode = Enum('OutputMode', ['BOFHound', 'BloodHound', 'Objects'])

    def __init__(self, snapfile, outputfolder, console=None, snapshot_parser=None):
        self.console = console or setup_logging()
        self.output = outputfolder

        if not snapshot_parser:
            from adexpsnapshot.parser.classes import Snapshot
            snapshot_parser = Snapshot

        self.snapfile = snapfile
        self.snap = snapshot_parser(snapfile)

        self.snap.parseHeader()

        filetimeiso = datetime.datetime.fromtimestamp(self.snap.header.filetimeUnix).isoformat()
        logging.info(f'Server: {self.snap.header.server}')
        logging.info(f'Time of snapshot: {filetimeiso}')
        logging.info('Mapping offset: 0x{:x}'.format(self.snap.header.mappingOffset))
        logging.info(f'Object count: {self.snap.header.numObjects}')

        self.snap.parseProperties()
        self.snap.parseClasses()
        self.snap.parseObjectOffsets()

        self.sidcache = {}
        self.dncache = CaseInsensitiveDict()
        self.computersidcache = CaseInsensitiveDict()
        self.domains = CaseInsensitiveDict()
        self.objecttype_guid_map = CaseInsensitiveDict()
        self.domaincontrollers = []
        self.rootdomain = None
        self.certtemplates = defaultdict(set)

    def preprocess(self, cache=False):
        if cache:
            cacheFileName = self.snapfile.name.replace(".dat", ".cache")

            dico = None
            try:
                dico = Unpickler(open(cacheFileName, "rb")).load()
            except (OSError, IOError, EOFError) as e:
                pass

            if dico and dico.get('unixtime') == self.snap.header.filetimeUnix:
                self.objecttype_guid_map = dico['guidmap']
                self.sidcache = dico['sidcache']
                self.dncache = dico['dncache']
                self.computersidcache = dico['computersidcache']
                self.domains = dico['domains']
                self.domaincontrollers = dico['domaincontrollers']
                self.rootdomain = dico['rootdomain']
                self.certtemplates = dico['certtemplates']

                self.console.print(f"[green]✓[/green] Using cached data for preprocessing")
                return

        for k, cl in self.snap.classes.items():
            self.objecttype_guid_map[k] = str(cl.schemaIDGUID)

        for k, idx in self.snap.propertyDict.items():
            self.objecttype_guid_map[k] = str(self.snap.properties[idx].schemaIDGUID)

        for idx, obj in track(enumerate(self.snap.objects), description="Preprocessing", total=self.snap.header.numObjects):
            # create sid cache
            objectSid = ADUtils.get_entry_property(obj, 'objectSid')
            if objectSid:
                self.sidcache[str(objectSid)] = idx

            # create dn cache
            distinguishedName = ADUtils.get_entry_property(obj, 'distinguishedName')
            if distinguishedName:
                self.dncache[str(distinguishedName)] = idx

            # get domains
            if 'domain' in obj.classes:
                if self.rootdomain is not None:  # is it possible to find multiple?
                    logging.warning("Multiple domains in snapshot(?)")
                else:
                    self.rootdomain = str(distinguishedName)
                    self.domains[str(distinguishedName)] = idx

            # get forest domains
            if 'crossref' in obj.classes:
                if ADUtils.get_entry_property(obj, 'systemFlags', 0) & 2 == 2:
                    ncname = ADUtils.get_entry_property(obj, 'nCName')
                    if ncname and ncname not in self.domains:
                        self.domains[str(ncname)] = idx

            # get computers
            if ADUtils.get_entry_property(obj, 'sAMAccountType', -1) == 805306369:
                dnshostname = ADUtils.get_entry_property(obj, 'dNSHostname')
                if dnshostname:
                    self.computersidcache[str(dnshostname)] = str(objectSid)

            # get all cert templates
            if 'pkienrollmentservice' in obj.classes:
                name = str(ADUtils.get_entry_property(obj, 'name'))
                if ADUtils.get_entry_property(obj, 'certificateTemplates'):
                    templates = ADUtils.get_entry_property(obj, 'certificateTemplates')
                    for template in templates:
                        self.certtemplates[str(template)].add(name)

            # get dcs
            if ADUtils.get_entry_property(obj, 'userAccountControl', 0) & 0x2000 == 0x2000:
                self.domaincontrollers.append(idx)

        if cache:
            dico = {
                'guidmap': self.objecttype_guid_map,
                'sidcache': self.sidcache,
                'dncache': self.dncache,
                'computersidcache': self.computersidcache,
                'domains': self.domains,
                'domaincontrollers': self.domaincontrollers,
                'rootdomain': self.rootdomain,
                'certtemplates': self.certtemplates,
                'unixtime': self.snap.header.filetimeUnix
            }
            with open(cacheFileName, "wb") as f:
                Pickler(f).dump(dico)
            self.console.print(f"[green]✓[/green] Cache saved to {cacheFileName}")
        
        self.console.print(f"[green]✓[/green] Preprocessing complete")

    def preprocessCached(self):
        """Alias for preprocess() for backward compatibility with scripts."""
        self.preprocess(cache=True)

    def outputObjects(self):
        """Output all objects to NDJSON file."""
        from adexpsnapshot.ouput.objects import ObjectsOutput
        handler = ObjectsOutput(self.snap, self.output, self.console)
        handler.process()

    def outputBOFHound(self):
        """Output objects in BOFHound log format."""
        from adexpsnapshot.ouput.bofhound import BOFHoundOutput
        handler = BOFHoundOutput(self.snap, self.output, self.console)
        handler.process()

    def outputBloodHound(self):
        """Output data in BloodHound JSON format."""

        logging.warning("The BloodHound mode gives incomplete output. Please use the BOFHound mode instead.")

        self.preprocess(cache=True)
        from adexpsnapshot.ouput.bloodhound import BloodHoundOutput
        handler = BloodHoundOutput(
            self.snap, self.output, self.console,
            self.sidcache, self.dncache, self.computersidcache, self.domains,
            self.objecttype_guid_map, self.domaincontrollers, self.rootdomain, self.certtemplates
        )
        handler.process()


def setup_logging(level=logging.INFO):
    console = Console()
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        markup=True
    )
    
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[rich_handler]
    )
    
    return console


def main():

    parser = argparse.ArgumentParser(add_help=True, description='AD Explorer snapshot ingestor for BloodHound', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('snapshot', type=argparse.FileType('rb'), help="Path to the snapshot .dat file.")
    parser.add_argument('-o', '--output', required=False, type=pathlib.Path, help="Path to an output folder. Folder will be created if it doesn't exist. Defaults to the current directory.", default=".")
    parser.add_argument('-m', '--mode', required=False, help="The output mode to use. Defaults to BOFHound output mode, which can then be used with BOFHound. Can also directly output to BloodHound JSON output files (with limitations). In Objects mode all objects with all attributes are outputted to NDJSON.", choices=ADExplorerSnapshot.OutputMode.__members__, default='BOFHound')

    args = parser.parse_args()

    if not os.path.exists(args.output):
        try:
            os.mkdir(args.output)
        except:
            logging.error(f"Unable to create output directory '{args.output}'.")
            return
    
    if not os.path.isdir(args.output):
        logging.warning(f"Path '{args.output}' does not exist or is not a folder.")
        parser.print_help()
        return
    
    ades = ADExplorerSnapshot(args.snapshot, args.output)

    outputmode = ADExplorerSnapshot.OutputMode[args.mode]
    if outputmode == ADExplorerSnapshot.OutputMode.BloodHound:
        ades.outputBloodHound()
    if outputmode == ADExplorerSnapshot.OutputMode.Objects:
        ades.outputObjects()
    if outputmode == ADExplorerSnapshot.OutputMode.BOFHound:
        ades.outputBOFHound()

if __name__ == '__main__':
    main()
