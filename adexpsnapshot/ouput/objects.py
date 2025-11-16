"""Objects output mode - outputs all objects as NDJSON."""
import codecs
import json
import base64
import logging
import os
import queue
import threading
from rich.console import Console
from rich.progress import track


class ObjectsOutput:
    """Handles Objects-specific output processing."""
    
    def __init__(self, snapshot, output_folder, console: Console):
        self.snap = snapshot
        self.output = output_folder
        self.console = console
        self.outputfile = f"{snapshot.header.server}_{snapshot.header.filetimeUnix}_objects.ndjson"

    def process(self):
        """Process all objects and output to NDJSON file."""
        class BaseSafeEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, bytes):
                    return base64.b64encode(obj).decode("ascii")
                return json.JSONEncoder.default(self, obj)

        def write_worker(result_q, filename):
            try:
                fh_out = codecs.open(filename, 'w', 'utf-8')
            except:
                logging.warning('Could not write file: %s', filename)
                result_q.task_done()
                return

            wroteOnce = False
            while True:
                data = result_q.get()

                if data is None:
                    break

                if not wroteOnce:
                    wroteOnce = True
                else:
                    fh_out.write('\n')

                try:
                    encoded_member = json.dumps(data, indent=None, cls=BaseSafeEncoder)
                    fh_out.write(encoded_member)
                except TypeError:
                    logging.error('Data error {0}, could not convert data to json'.format(repr(data)))
                result_q.task_done()

            fh_out.close()
            result_q.task_done()
            
        wq = queue.Queue()
        results_worker = threading.Thread(target=write_worker, args=(wq, os.path.join(self.output, self.outputfile)))
        results_worker.daemon = True
        results_worker.start()

        for idx, obj in track(enumerate(self.snap.objects), description="Dumping objects", total=self.snap.header.numObjects):
            wq.put((dict(obj.attributes.data)))

        wq.put(None)
        wq.join()

        self.console.print(f"[green]✓[/green] Output written to {self.outputfile}")
